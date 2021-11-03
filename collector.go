// Copyright 2019 Michael DOUBEZ
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os/user"
	"syscall"
//	"strconv"
	"bytes"
	"hash/crc32"
	"io"
	"os"
	"path"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
)

const namespace = "file"

var (
	fileMatchingGlobNbDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "glob", "match_number"),
		"Number of files matching pattern",
		[]string{"pattern"}, nil,
	)
	fileSizeBytesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "stat", "size_bytes"),
		"Size of file in bytes",
		[]string{"path","user","group"}, nil,
	)
//	fileOwner = prometheus.NewDesc(
//		prometheus.BuildFQName(namespace, "stat", "user"),
//		"Owner of File",
//		[]string{"metric"}, nil,
//	)
//	fileGroup = prometheus.NewDesc(
//		prometheus.BuildFQName(namespace, "stat", "group"),
//		"Group of File",
//		[]string{"metric"}, nil,
//	)
	fileModifTimeSecondsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "stat", "modif_time_seconds"),
		"Last modification time of file in epoch time",
		[]string{"path"}, nil,
	)
	fileCRC32HashDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "content", "hash_crc32"),
		"CRC32 hash of file content using the IEEE polynomial",
		[]string{"path"}, nil,
	)
	lineNbMetricDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "content", "line_number"),
		"Number of lines in file",
		[]string{"path"}, nil,
	)
)

// Collector compute metrics for each file matching the patterns
type fileStatCollector struct {
	filesPatterns      []string
	enableCRC32Metric  bool
	enableLineNbMetric bool
}

// Files collector
type filesCollector struct {
	collectors []fileStatCollector

	atLeastOneCRC32Metric  bool
	atLeastOneLineNbMetric bool

	logger log.Logger
}

// Describe implements the prometheus.Collector interface.
func (c *filesCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- fileMatchingGlobNbDesc
	ch <- fileSizeBytesDesc
//	ch <- fileOwner
//	ch <- fileGroup
	ch <- fileModifTimeSecondsDesc
	if c.atLeastOneCRC32Metric {
		ch <- fileCRC32HashDesc
	}
	if c.atLeastOneLineNbMetric {
		ch <- lineNbMetricDesc
	}
}

// Collect implements the prometheus.Collector interface.
func (c *filesCollector) Collect(ch chan<- prometheus.Metric) {
	patternSet := make(map[string]struct{})
	fileSet := make(map[string]struct{})
	for _, collector := range c.collectors {
		for _, pattern := range collector.filesPatterns {
			// only collect pattern once
			if _, ok := patternSet[pattern]; ok {
				continue
			}
			patternSet[pattern] = struct{}{}

			// get files matching pattern
			matchingFileNb := 0
			basepath, patternPart := doublestar.SplitPattern(pattern)
			fsys := os.DirFS(basepath)
			if matches, err := doublestar.Glob(fsys, patternPart); err == nil {
				for _, filePath := range matches {
					fqPath := path.Join(basepath, filePath)
					// only collect files once
					level.Debug(c.logger).Log("msg", "Collecting file", "path", fqPath)
					if _, ok := fileSet[fqPath]; ok {
						continue
					}
					fileSet[fqPath] = struct{}{}

					if collectFileMetrics(ch, fqPath, &matchingFileNb, c.logger) {
						if collector.enableCRC32Metric || collector.enableLineNbMetric {
							collectContentMetrics(ch, fqPath,
								collector.enableCRC32Metric,
								collector.enableLineNbMetric,
								c.logger)
						}
					}
				}
			} else {
				level.Debug(c.logger).Log("msg", "Error getting matches for glob", "pattern", pattern, "reason", err)
			}
			ch <- prometheus.MustNewConstMetric(fileMatchingGlobNbDesc, prometheus.GaugeValue,
				float64(matchingFileNb),
				pattern)
		}
	}
}

func groupLookup(gid string) (string, error) {
	g, err := user.LookupGroupId(gid)
	if err != nil {
		return "", err
	}
	return g.Name, nil
}

func userLookup(uid string) (string, error) {
	u, err := user.LookupId(uid)
	if err != nil {
		return "", err
	}
	return u.Name, nil
}
// Collect metrics for a file and feed
func collectFileMetrics(ch chan<- prometheus.Metric, filePath string, nbFile *int, logger log.Logger) bool {
	// Metrics based on Fileinfo
	if fileinfo, err := os.Stat(filePath); err == nil {
		if fileinfo.IsDir() {
			return false
		}
		*nbFile++

		file_sys := fileinfo.Sys()
		gid := fmt.Sprint(file_sys.(*syscall.Stat_t).Gid)
		uid := fmt.Sprint(file_sys.(*syscall.Stat_t).Uid)

		group, err := groupLookup(gid)
		if err == nil {
		//	fmt.Print("Group  is ", group, " \n")
		}

		user, err := userLookup(uid)
		if err == nil {
		//	fmt.Print("User  is ", user, " \n")
		}

		//f, err := strconv.ParseFloat(uid, 8)
		//if err == nil {
		//		fmt.Println(f, err, reflect.TypeOf(f))
		//}


		//g, err := strconv.ParseFloat(gid, 8)
		//if err == nil {
		//		fmt.Println(g, err, reflect.TypeOf(g))
		//}




		//str2 := [2]string{filePath,group}

//	ch <- prometheus.MustNewConstMetric(
//					prometheus.NewDesc(prometheus.BuildFQName(namespace, "stat", "fileuser"),
//						"File Owner", []string{"metric"}, nil),
//					prometheus.GaugeValue, f, filePath ,
//				)
//		ch <- prometheus.MustNewConstMetric(
//					prometheus.NewDesc(prometheus.BuildFQName(namespace, "stat", "filepermissions"),
//						"File Group", []string{"metric","user","group"}, nil),
//					prometheus.GaugeValue, 1 ,filePath,user,group,
//				)
		ch <- prometheus.MustNewConstMetric(fileSizeBytesDesc, prometheus.GaugeValue,
			float64(fileinfo.Size()),
			filePath,user,group)
//		ch <- prometheus.MustNewConstMetric(fileOwner, prometheus.GaugeValue,
//			f,
//			filePath)
//		ch <- prometheus.MustNewConstMetric(fileGroup, prometheus.GaugeValue,
//			g,
//			filePath)


		modTime := fileinfo.ModTime()
		ch <- prometheus.MustNewConstMetric(fileModifTimeSecondsDesc, prometheus.GaugeValue,
			float64(modTime.Unix())+float64(modTime.Nanosecond())/1000000000.0,
			filePath)
	} else {
		level.Debug(logger).Log("msg", "Error getting file info", "path", filePath, "reason", err)
		return false
	}
	return true
}

// Collect metrics for a file content
func collectContentMetrics(ch chan<- prometheus.Metric, filePath string,
	enableCRC32 bool, enableLineNb bool, logger log.Logger) {
	file, err := os.Open(filePath)
	if err != nil {
		level.Debug(logger).Log("msg", "Error getting content file hash while opening", "path", filePath, "reason", err)
		return
	}
	defer file.Close()

	hash := crc32.NewIEEE()
	lineNb := 0

	// read chunks of 32k
	buf := make([]byte, 32*1024)
	lineSep := []byte{'\n'}

ReadFile:
	for {
		c, err := file.Read(buf)
		slice := buf[:c]
		if enableLineNb {
			lineNb += bytes.Count(slice, lineSep)
		}
		if enableCRC32 {
			if _, errHash := hash.Write(slice); errHash != nil {
				level.Debug(logger).Log("msg", "Error generating CRC32 hash of file", "path", filePath, "reason", errHash)
				enableCRC32 = false
			}
		}

		switch {
		case err == io.EOF:
			break ReadFile

		case err != nil:
			level.Debug(logger).Log("msg", "Error reading content of file", "path", filePath, "reason", err)
			return
		}
	}

	if enableCRC32 {
		ch <- prometheus.MustNewConstMetric(fileCRC32HashDesc, prometheus.GaugeValue,
			float64(hash.Sum32()),
			filePath)
	}
	if enableLineNb {
		ch <- prometheus.MustNewConstMetric(lineNbMetricDesc, prometheus.GaugeValue,
			float64(lineNb),
			filePath)
	}
}
