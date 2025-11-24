package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
)

// GetAccessToken performs the OAuth2 client_credentials flow to get a new access token.
// This is a standalone function, separate from the API client,
// as the token is usually retrieved once during provider configuration.
func GetAccessToken(ctx context.Context, host, clientID, clientSecret string, insecure bool) (*AuthResponse, error) {

	// 1. Prepare the request payload
	authPayload := AuthRequest{
		GrantType:    "client_credentials",
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}

	payloadBytes, err := json.Marshal(authPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal auth request: %w", err)
	}

	// 2. Create the HTTP client
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
	httpClient := &http.Client{Transport: tr}

	// 3. Create the HTTP request
	authURL := "https://" + host + "/api/oauth" // Your auth URL
	req, err := http.NewRequestWithContext(ctx, "POST", authURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create auth request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// 4. Execute the request
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send auth request: %w", err)
	}
	defer func() {
		cerr := resp.Body.Close()
		if cerr != nil {
			// Optionally log or handle the error, but do not shadow the main error
			fmt.Printf("warning: error closing response body: %v\n", cerr)
		}
	}()

	// 5. Check for non-OK status
	if resp.StatusCode != http.StatusOK {
		// Try to parse it as an ApiError, but fall back to a generic error
		var apiErr ApiError
		if json.NewDecoder(resp.Body).Decode(&apiErr) == nil {
			apiErr.StatusCode = resp.StatusCode
			return nil, &apiErr
		}
		return nil, fmt.Errorf("auth failed with status code: %d", resp.StatusCode)
	}

	// 6. Decode the successful response
	var authResponse AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		return nil, fmt.Errorf("failed to decode auth response: %w", err)
	}

	return &authResponse, nil
}
