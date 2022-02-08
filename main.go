package main

// https://www.kernel.org/doc/Documentation/vm/pagemap.txt

import (
	"encoding/binary"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	flag "github.com/spf13/pflag"
	"go.uber.org/atomic"
)

const (
	FILES_BATCH    = 1 << 10
	PAGEMAP_BATCH  = 64 << 10
	PAGEMAP_LENGTH = int64(8)
	SIZEOF_INT64   = 8 // bytes
	PFN_MASK       = 0x7FFFFFFFFFFFFF
	PAGE_SIZE      = 4 * 1024 // bytes
)

var (
	debug    bool
	mount    string
	verbose  bool
	follow   bool
	maxDepth uint

	pageSize = int64(syscall.Getpagesize())
	mode     = os.FileMode(0600)

	units = []string{"B", "K", "M", "G", "T", "P", "E"}
)

func init() {
	flag.BoolVarP(&debug, "debug", "d", false, "debug mode provides more info")
	flag.BoolVarP(&verbose, "verbose", "v", false, "verbose mode outputs per file info")
	flag.BoolVarP(&follow, "follow", "f", false, "follow symbolic links")
	flag.UintVarP(&maxDepth, "max-depth", "p", 12, "max depth walk in dirs")
	flag.StringVarP(&mount, "mount", "m", "/sys/fs/cgroup/", "memory cgroup mount point (by default v2 version)")
}

type Cgroup struct {
	Inode   uint64
	Path    string
	Charged uint64
}

type Cgroups map[uint64]*Cgroup

type File struct {
	Path    string
	Size    int64
	Pages   int64
	Charged uint64
	Cgroups Cgroups
}

type Files map[string]*File

type Stats struct {
	Charged     atomic.Uint64
	Size        atomic.Int64
	Pages       atomic.Int64
	watchedDirs atomic.Int64

	m       *sync.Mutex
	Cgroups Cgroups
	Files   Files

	pagemap     *os.File
	kpagecgroup *os.File

	WG    *sync.WaitGroup
	errs  chan error
	paths chan string
}

func NewStats() (*Stats, error) {
	pagemap, err := os.OpenFile("/proc/self/pagemap", os.O_RDONLY, mode)
	if err != nil {
		return nil, err
	}

	kpagecgroup, err := os.OpenFile("/proc/kpagecgroup", os.O_RDONLY, mode)
	if err != nil {
		return nil, err
	}

	wg := &sync.WaitGroup{}

	stats := &Stats{
		m:           &sync.Mutex{},
		pagemap:     pagemap,
		kpagecgroup: kpagecgroup,
		errs:        make(chan error, FILES_BATCH),
		paths:       make(chan string, FILES_BATCH),
		Cgroups:     make(Cgroups),
		Files:       make(Files),
		WG:          wg,
	}

	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			for fn := range stats.paths {
				err := stats.HandleFile(fn)
				if err != nil {
					stats.errs <- err
				}
			}
			wg.Done()
		}()
	}

	go func() {
		wg.Wait()
		close(stats.errs)
	}()

	return stats, nil
}

func (st *Stats) Close() error {
	_ = st.kpagecgroup.Close()
	_ = st.pagemap.Close()
	return nil
}

func (st *Stats) HandleFile(path string) error {
	stat, err := os.Lstat(path)
	if err != nil {
		return err
	}

	if stat.Mode()&os.ModeSymlink == os.ModeSymlink {
		return fmt.Errorf("symlinks don't allowed: %s", path)
	}

	if stat.IsDir() {
		return err
	}

	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NOATIME, mode)
	if err != nil {
		return err
	}
	defer file.Close()

	size := stat.Size()
	pages := size/pageSize + 1

	f := &File{
		Cgroups: make(Cgroups),
		Pages:   pages,
		Size:    size,
		Path:    path,
	}
	st.m.Lock()
	st.Files[path] = f
	st.m.Unlock()

	st.Pages.Add(pages)
	st.Size.Add(size)

	var batch int64
	var buf []byte
	for off := int64(0); off < size; off += batch {
		buf, batch, err = st.handleBatch(file, off, size)
		if err != nil {
			return err
		}

		data := make([]uint64, len(buf)/SIZEOF_INT64)
		for i := range data {
			data[i] = binary.LittleEndian.Uint64(buf[i*SIZEOF_INT64:])
		}

		cgroup := make([]byte, 8)
		for _, d := range data {
			pfn := d & PFN_MASK
			if pfn == 0 {
				continue
			}

			_, err := st.kpagecgroup.ReadAt(cgroup, int64(pfn)*PAGEMAP_LENGTH)
			if err != nil {
				return err
			}

			ci := binary.LittleEndian.Uint64(cgroup)

			// update per file
			if _, ok := f.Cgroups[ci]; ok {
				f.Cgroups[ci].Charged += 1
			} else {
				f.Cgroups[ci] = &Cgroup{
					Charged: 1,
					Inode:   ci,
				}
			}

			// update for all cgroup
			st.m.Lock()
			if _, ok := st.Cgroups[ci]; ok {
				st.Cgroups[ci].Charged += 1
			} else {
				st.Cgroups[ci] = &Cgroup{
					Charged: 1,
					Inode:   ci,
				}
			}
			st.m.Unlock()

			// update total
			st.Charged.Inc()
			f.Charged++

			if debug {
				fmt.Printf("cgroup memory inode for pfn %x: %d\n", pfn, ci)
			}
		}
	}

	return err
}

func (st *Stats) handleBatch(f *os.File, off, size int64) (buf []byte, batch int64, err error) {
	np := (size - off + pageSize - 1) / pageSize
	if np > PAGEMAP_BATCH {
		np = PAGEMAP_BATCH
	}
	batch = np * pageSize

	var mm []byte
	mm, err = syscall.Mmap(int(f.Fd()), off, int(batch), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, 0, err
	}

	defer func() {
		sErr := syscall.Munmap(mm)
		if sErr != nil {
			err = sErr
		}
	}()

	// disable readahead
	err = syscall.Madvise(mm, syscall.MADV_RANDOM)
	if err != nil {
		return nil, 0, err
	}

	defer func() {
		// reset referenced flags
		sErr := syscall.Madvise(mm, syscall.MADV_SEQUENTIAL)
		if sErr != nil {
			err = sErr
		}
	}()

	// mincore for finding out pages in page cache
	mmPtr := uintptr(unsafe.Pointer(&mm[0]))

	mincoreSize := (batch + int64(pageSize) - 1) / int64(pageSize)
	mincoreVec := make([]byte, mincoreSize)

	ret, _, errno := syscall.Syscall(syscall.SYS_MINCORE, mmPtr, uintptr(batch), uintptr(unsafe.Pointer(&mincoreVec[0])))
	if ret != 0 {
		return nil, 0, fmt.Errorf("syscall SYS_MINCORE failed: %v", errno)
	}

	for i, v := range mincoreVec {
		if v&1 == 1 {
			// load pages to PTE
			_ = *(*int)(unsafe.Pointer(mmPtr + uintptr(pageSize*int64(i))))
		}
	}

	index := int64(mmPtr) / pageSize * PAGEMAP_LENGTH
	buf = make([]byte, np*PAGEMAP_LENGTH)

	_, err = st.pagemap.ReadAt(buf, index)
	if err != nil {
		return nil, 0, err
	}

	return buf, batch, nil
}

func (st *Stats) Handle(paths []string, depth uint) chan error {
	for _, path := range paths {
		if debug {
			fmt.Println("Working with path: ", path)
		}

		// get stat
		stat, err := os.Lstat(path)
		if err != nil {
			st.errs <- err
			continue
		}

		// check on symlink
		if stat.Mode()&os.ModeSymlink == os.ModeSymlink {
			if follow {
				path, err = filepath.EvalSymlinks(path)
				if err != nil {
					st.errs <- err
					continue
				}
				stat, err = os.Lstat(path)
				if err != nil {
					st.errs <- err
					continue
				}
			} else {
				st.errs <- fmt.Errorf("Don't follow symlinks for %s. If you want then use \"-f\" flag", path)
				continue
			}
		}

		// check of file type
		if stat.IsDir() {
			// it is directory
			st.watchedDirs.Inc()

			if depth+1 > maxDepth {
				st.errs <- fmt.Errorf("max depth reached for %s", path)
				continue
			}

			// get file list
			files, err := ioutil.ReadDir(path)
			if err != nil {
				st.errs <- err
				continue
			}

			// make new depth step
			fs := make([]string, 0)
			for _, file := range files {
				fs = append(fs, filepath.Join(path, file.Name()))
			}
			st.Handle(fs, depth+1)
		} else if stat.Mode().IsRegular() {
			// it's regular file
			st.paths <- path
		} else {
			// it's something else: device, pipe, socket
			st.errs <- fmt.Errorf("%s is not a regular file", path)
		}
	}

	if depth == 0 {
		close(st.paths)
	}
	return st.errs
}

func ByteSize(bytes int64) string {
	value := float64(bytes)

	var i int
	for i = 0; value >= 1024 && i < len(units)-1; i++ {
		value /= 1024
	}
	var unit = units[i]

	stringValue := fmt.Sprintf("%.1f", value)
	stringValue = strings.TrimSuffix(stringValue, ".0")
	return fmt.Sprintf("%s%s", stringValue, unit)
}

func printCgroupStats(cgroups Cgroups, charged uint64, pages int64) {
	fmt.Printf("%12s%11s%12s%12s\n", "cgroup inode", "percent", "pages", "path")

	fmt.Printf("%12s%10.1f%%%12d        %s\n", "-",
		float64(uint64(pages)-charged)*100/float64(pages),
		uint64(pages)-charged,
		"not charged",
	)

	resolved, err := ResolveCgroups()
	if err != nil {
		fmt.Printf("cgroup resolution failed: %s\n", err)
		return
	}

	for _, c := range cgroups {
		var pt string
		if cg, ok := resolved[c.Inode]; !ok {
			pt = fmt.Sprintf("cgroup not resolved: %d", c.Inode)
		} else {
			pt = cg.Path
		}

		p := float64(c.Charged) * 100 / float64(pages)
		fmt.Printf("%12d%10.1f%%%12d        %s\n", c.Inode, p, c.Charged, pt)
	}
}

func ResolveCgroups() (map[uint64]Cgroup, error) {
	cgroups := make(map[uint64]Cgroup)
	err := fs.WalkDir(os.DirFS(mount), ".", func(path string, d fs.DirEntry, _ error) error {
		if !d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		cgroups[stat.Ino] = Cgroup{
			Path:  filepath.Join(mount, path),
			Inode: stat.Ino,
		}
		return nil
	})
	return cgroups, err
}

func main() {
	flag.Parse()

	stat, err := NewStats()
	if err != nil {
		log.Fatalln(err)
	}
	defer stat.Close()

	errs := stat.Handle(flag.Args(), 0)
	for err := range errs {
		fmt.Println("Warning: ", err)
	}

	// print per file stats
	if verbose {
		for _, f := range stat.Files {
			fmt.Println(f.Path)
			printCgroupStats(f.Cgroups, f.Charged, f.Pages)
			fmt.Printf("\n--\n")
		}
	}

	// calculate total
	sc := stat.Charged.Load() * PAGE_SIZE
	if int64(sc) > stat.Size.Load() {
		sc = uint64(stat.Size.Load())
	}
	percent := float64(sc*100) / float64(stat.Size.Load())

	// print total
	fmt.Printf("%14s: %d\n", "Files", len(stat.Files))
	fmt.Printf("%14s: %d\n", "Directories", stat.watchedDirs.Load())
	fmt.Printf("%14s: %d/%d %s/%s %.1f%%\n\n",
		"Resident Pages",
		stat.Charged.Load(),
		stat.Pages.Load(),
		ByteSize(int64(sc)),
		ByteSize(stat.Size.Load()),
		percent,
	)

	// print per cgroup total
	printCgroupStats(stat.Cgroups, stat.Charged.Load(), stat.Pages.Load())

}
