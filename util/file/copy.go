package file

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func CopyDir(srcPath string, destPath string) error {
	if srcInfo, err := os.Stat(srcPath); err != nil {
		return err
	} else {
		if !srcInfo.IsDir() {
			e := errors.New("srcPath is not a correct dir")
			return e
		}
	}
	if destInfo, err := os.Stat(destPath); err != nil {
		e := os.MkdirAll(destPath, os.ModePerm)
		if e != nil {
			return e
		}
	} else {
		if !destInfo.IsDir() {
			e := errors.New("destInfo is not a correct dir")
			return e
		}
	}

	err := filepath.Walk(srcPath, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			return err
		}
		if !f.IsDir() {
			path := strings.Replace(path, "\\", "/", -1)
			destNewPath := strings.Replace(path, srcPath, destPath, -1)
			err := CopyFile(path, destNewPath)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func CopyFile(src, dest string) (err error) {
	srcFile, err := os.Open(src)
	if err != nil {
		return
	}
	defer srcFile.Close()

	destSplitPathDirs := strings.Split(dest, "/")

	destSplitPath := ""
	for index, dir := range destSplitPathDirs {
		if index < len(destSplitPathDirs)-1 {
			destSplitPath = destSplitPath + dir + "/"
			b, _ := PathExists(destSplitPath)
			if b == false {
				err := os.Mkdir(destSplitPath, os.ModePerm)
				if err != nil {
					return err
				}
			}
		}
	}
	dstFile, err := os.Create(dest)
	defer dstFile.Close()
	if err != nil {
		return err
	}
	if _, err = io.Copy(dstFile, srcFile); err != nil {
		return err
	}
	return nil
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
