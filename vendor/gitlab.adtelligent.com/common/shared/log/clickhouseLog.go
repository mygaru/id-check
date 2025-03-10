// The package shouldn't import lib/* packages outside lib/log in order to avoid
// log recursion!

package log

import (
	"flag"
	"github.com/valyala/fasthttp"
	"gitlab.adtelligent.com/common/shared/batcher"
	"gitlab.adtelligent.com/common/shared/log/internal/baselog"
	"gitlab.adtelligent.com/common/shared/log/internal/clickhouseClient"
	"sync/atomic"
	"time"
)

var (
	clickhouseLogDatabase = flag.String("clickhouseLogDatabase", "log", "Database to write logs to")
	clickhouseLogTable    = flag.String("clickhouseLogTable", "logs_buffer", "Table to write logs to")
	clickhouseLogAddr     = flag.String("clickhouseLogAddr", "",
		"TCP address of clickhouse server for pushing logs to. "+
			"Logs are written only to stdout/stderr if empty")
	clickhouseLogMaxBatchSize = flag.Int("clickhouseLogMaxBatchSize", 1000,
		"Maximum batch size before pushing logs to clickhouse")
	clickhouseLogMaxConcurrentBatches = flag.Int("clickhouseLogMaxConcurrentBatches", 5,
		"Maximum number of concurrent batch inserts to clickhouse")
	clickhouseLogMaxRetries = flag.Int("clickhouseLogMaxRetries", 10,
		"Maximum number of batch insert retries to clickhouse in case of errors")

	clickhouseUser     = flag.String("clickhouseLogUser", "", "User for writing adstats to clickhouse")
	clickhousePassword = flag.String("clickhouseLogPassword", "", "Passed for writing adstats to clickhouse")
)

var concurrentBatchesCh chan struct{}

func clickhouseInit() {
	concurrentBatchesCh = make(chan struct{}, *clickhouseLogMaxConcurrentBatches)
	clickhouseLogBatcher = &batcher.BytesBatcher{
		BatchFunc: concurrentPushBatchToDB,
		HeaderFunc: func(b []byte) []byte {
			b = append(b, "INSERT INTO "...)
			b = append(b, *clickhouseLogDatabase...)
			b = append(b, '.')
			b = append(b, *clickhouseLogTable...)
			b = append(b, " (\n"...)
			b = append(b, logsFields...)
			b = append(b, "\n) FORMAT RowBinary\n"...)
			return b
		},
		MaxBatchSize: *clickhouseLogMaxBatchSize,
		MaxDelay:     200 * time.Millisecond,
	}
	client = clickhouseClient.New(*clickhouseLogAddr)
	if *clickhouseUser != "" {
		client.SetAuth(*clickhouseUser, *clickhousePassword)
	}

	baselog.Infof("pushing log messages to %q %q:%q", *clickhouseLogAddr, *clickhouseLogDatabase, *clickhouseLogTable)
}

const logsFields = `
	LogID,
	LogLevel,
	AppName,
	AppIP,
	AppID,
	AppVersion,
	AppFile,
	AppLine,
	LogMessage
	`

type logRecord struct {
	LogLevel   string
	AppName    string
	AppIP      uint32
	AppID      string
	AppVersion string
	AppFile    string
	AppLine    uint32
	LogMessage string
}

func (lr *logRecord) appendRow(b []byte) []byte {
	logID := atomic.AddUint64(&globalLogID, 1)
	b = AppendUint64(b, logID)
	b = AppendString(b, lr.LogLevel)
	b = AppendString(b, lr.AppName)
	b = AppendUint32(b, lr.AppIP)
	b = AppendString(b, lr.AppID)
	b = AppendString(b, lr.AppVersion)
	b = AppendString(b, lr.AppFile)
	b = AppendUint32(b, lr.AppLine)
	b = AppendString(b, lr.LogMessage)
	return b
}

var globalLogID = uint64(time.Now().UnixNano())

var (
	client               *clickhouseClient.Client
	clickhouseLogBatcher *batcher.BytesBatcher
)

func concurrentPushBatchToDB(sql []byte, itemsCount int) {
	select {
	case concurrentBatchesCh <- struct{}{}:
		sqlCompressed := fasthttp.AppendGzipBytesLevel(nil, sql, 4)
		go func() {
			pushBatchToDB(sqlCompressed, itemsCount)
			<-concurrentBatchesCh
		}()
	default:
		baselog.Errorf("concurrent insert batches' limit %d exceeded when pushing to %q",
			*clickhouseLogMaxConcurrentBatches, *clickhouseLogAddr)
	}
}

func pushBatchToDB(sqlCompressed []byte, itemsCount int) {
	attemptsCount := 0
	for {
		err := client.BatchInsertCompressed(sqlCompressed)
		if err == nil {
			return
		}

		attemptsCount++
		if attemptsCount >= *clickhouseLogMaxRetries {
			baselog.Errorf("error while inserting clickhouse batch to %q: %s", *clickhouseLogAddr, err)
			return
		}
	}
}
