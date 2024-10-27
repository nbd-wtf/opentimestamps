package opentimestamps

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
)

func Stamp(ctx context.Context, calendarUrl string, digest [32]byte) (Sequence, error) {
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

	seq, err := parseCalendarServerResponse(newBuffer(full))
	if err != nil {
		return nil, fmt.Errorf("failed to parse response from '%s': %w", calendarUrl, err)
	}

	return seq, nil
}

func ReadFromFile(data []byte) (*File, error) {
	return parseOTSFile(newBuffer(data))
}

func UpgradeSequence(ctx context.Context, seq Sequence, initial []byte) (Sequence, error) {
	result, _ := seq.Compute(initial)
	attestation := seq.GetAttestation()

	url := fmt.Sprintf("%s/timestamp/%x", normalizeUrl(attestation.CalendarServerURL), result)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("User-Agent", "github.com/fiatjaf/opentimestamps")
	req.Header.Add("Accept", "application/vnd.opentimestamps.v1")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("'%s' request failed: %w", attestation.CalendarServerURL, err)
	}

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("'%s' returned %d", attestation.CalendarServerURL, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response from '%s': %w", attestation.CalendarServerURL, err)
	}
	resp.Body.Close()

	tail, err := parseCalendarServerResponse(newBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to parse response from '%s': %w", attestation.CalendarServerURL, err)
	}

	newSeq := make(Sequence, len(seq)+len(tail)-1)
	copy(newSeq, seq[0:len(seq)-1])
	copy(newSeq[len(seq)-1:], tail)

	return newSeq, nil
}
