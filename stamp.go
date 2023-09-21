package opentimestamps

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
)

func Stamp(ctx context.Context, calendarUrl string, digest [32]byte) error {
	body := bytes.NewBuffer(digest[:])
	req, err := http.NewRequestWithContext(ctx, "POST", normalizeUrl(calendarUrl)+"/digest", body)
	if err != nil {
		return err
	}

	req.Header.Add("User-Agent", "github.com/fiatjaf/opentimestamps")
	req.Header.Add("Accept", "application/vnd.opentimestamps.v1")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("'%s' request failed: %w", calendarUrl, err)
	}

	full, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response from '%s': %w", calendarUrl, err)
	}
	resp.Body.Close()

	fmt.Println("full", hex.EncodeToString(full))
	v, err := parseCalendarServerResponse(NewBuffer(full), digest[:])
	fmt.Println(err)
	fmt.Println(v)

	return nil
}
