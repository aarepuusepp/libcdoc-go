package central

import "fmt"

// ValidateNOfN enforces strict N-of-N key share recovery: every configured share is required.
func ValidateNOfN(shareCount, minRequired int) error {
	if shareCount < 2 {
		return fmt.Errorf("N-of-N requires at least 2 key shares")
	}
	if minRequired < 2 {
		return fmt.Errorf("N-of-N minRequired must be at least 2")
	}
	if shareCount != minRequired {
		return fmt.Errorf("N-of-N requires minRequired (%d) to equal share count (%d)", minRequired, shareCount)
	}
	return nil
}
