package main

import (
	"fmt"
	"github.com/tebeka/selenium"
	"github.com/tebeka/selenium/chrome"
	"testing"
	"time"
)

func (h *AuthHandler) TestRegisterUser(t *testing.T) {
	email := "tester@example.com"
	name := "new"
	password := "password123"
	confirmationToken := "test_token"
	tokenExpiration := time.Now().Add(24 * time.Hour)

	err := h.DB.RegisterUser(email, name, password, confirmationToken, tokenExpiration)

	err = h.DB.RegisterUser(email, name, password, confirmationToken, tokenExpiration)
	if err == nil {
		t.Error("Failed")
	}
	if err != nil {
		fmt.Println("Success")
	}
}

func TestJobsPage(t *testing.T) {
	const (
		seleniumPath     = ""
		chromeDriverPath = "C://Users/LEGION/Desktop/"
		port             = 8080
	)
	opts := []selenium.ServiceOption{}
	service, err := selenium.NewChromeDriverService(chromeDriverPath, port, opts...)
	if err != nil {
		t.Fatalf("Error starting the ChromeDriver server: %v", err)
	}
	defer service.Stop()

	caps := selenium.Capabilities{"browserName": "chrome"}
	chromeCaps := chrome.Capabilities{Path: "", Args: []string{
		"--headless", // Remove this if you want to see the browser window.
	}}
	caps.AddChrome(chromeCaps)

	wd, err := selenium.NewRemote(caps, "")
	if err != nil {
		t.Fatalf("Failed to open session: %v", err)
	}
	defer wd.Quit()

	// Replace with your application's jobs page URL.
	if err := wd.Get("http://localhost:8080/jobs"); err != nil {
		t.Fatalf("Failed to load page: %v", err)
	}

	// Example: Log in if necessary.
	// err = loginUser(wd)
	// if err != nil {
	// 	t.Fatalf("Failed to log in: %v", err)
	// }

	// Check for the presence of a specific element that indicates jobs are listed.
	// This will depend on your page's structure.
	_, err = wd.FindElement(selenium.ByCSSSelector, ".job-listing")
	if err != nil {
		t.Fatalf("Job listings not found: %v", err)
	}

	// Optionally, validate job listing details.
	// e.g., check for job titles, company names, etc.

	// Note: Add any additional validations as needed.
}
