package archiver

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func CreateTarArchive(inputPath, outputPath string) error {
	output, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create an output file for archival: %v", err)
	}
	defer output.Close()

	tarWriter := tar.NewWriter(output)
	defer tarWriter.Close()

	err = filepath.Walk(inputPath, func(path string, info os.FileInfo, walkError error) error {
		if walkError != nil {
			return walkError
		}

		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("could not open file %s for reading: %v", path, err)
		}
		defer file.Close()

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("could not create a tar header for file %s : %v", path, err)
		}

		header.Name, err = filepath.Rel(inputPath, path)
		if err != nil {
			return fmt.Errorf("failed to calculate a relative file path of %s from %s", path, inputPath)
		}

		err = tarWriter.WriteHeader(header)
		if err != nil {
			return fmt.Errorf("failed to write header for the file %s : %v", path, err)
		}

		_, err = io.Copy(tarWriter, file)
		if err != nil {
			return fmt.Errorf("could not write file %s to tar archive: %v", path, err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("error while walking through input path: %v", err)
	}

	return nil
}

func ExtractTarArchive(inputPath, outputPath string) error {
	tarFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("could not open tar file: %v", err)
	}
	defer tarFile.Close()

	tarReader := tar.NewReader(tarFile)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("could not read tar header: %v", err)
		}

		filePath := filepath.Join(outputPath, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(filePath, 0755); err != nil {
				return fmt.Errorf("could not create directory: %v", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
				return fmt.Errorf("could not create directory for file: %v", err)
			}

			outFile, err := os.Create(filePath)
			if err != nil {
				return fmt.Errorf("could not create file %s: %v", filePath, err)
			}
			defer outFile.Close()

			if _, err := io.Copy(outFile, tarReader); err != nil {
				return fmt.Errorf("could not copy file contents: %v", err)
			}
		default:
			return fmt.Errorf("unknown tar header type: %v", header.Typeflag)
		}
	}

	return nil
}
