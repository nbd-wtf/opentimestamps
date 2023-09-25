package opentimestamps

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
)

func Stamp(ctx context.Context, calendarUrl string, digest [32]byte) (*Timestamp, error) {
	body := bytes.NewBuffer(digest[:])
	req, err := http.NewRequestWithContext(ctx, "POST", normalizeUrl(calendarUrl)+"/digest", body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("User-Agent", "github.com/fiatjaf/opentimestamps")
	req.Header.Add("Accept", "application/vnd.opentimestamps.v1")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("'%s' request failed: %w", calendarUrl, err)
	}

	full, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response from '%s': %w", calendarUrl, err)
	}
	resp.Body.Close()

	return parseCalendarServerResponse(NewBuffer(full), digest[:])
}

func ReadFromFile(data []byte) (*Timestamp, error) {
	return parseOTSFile(NewBuffer(data))
}

// func Upgrade(ctx context.Context, calendarUrl string) (*Timestamp, error) {
// 	body := bytes.NewBuffer(digest[:])
// 	req, err := http.NewRequestWithContext(ctx, "POST", normalizeUrl(calendarUrl)+"/timestamp/" +, nil)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	req.Header.Add("User-Agent", "github.com/fiatjaf/opentimestamps")
// 	req.Header.Add("Accept", "application/vnd.opentimestamps.v1")
// 	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
// 	resp, err := http.DefaultClient.Do(req)
// 	if err != nil {
// 		return nil, fmt.Errorf("'%s' request failed: %w", calendarUrl, err)
// 	}
//
// 	full, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to read response from '%s': %w", calendarUrl, err)
// 	}
// 	resp.Body.Close()
//
// 	return parseCalendarServerResponse(NewBuffer(full), digest[:])
// }
