package trojan

import "errors"

// If you use this module for your customer-facing application:
// For any error `trojan` module returned that is not in the list below, it is
// recommended that you retreat it as an internal/debugging-level error.
// Log it somewhere and show customer a SERIAL number for customer service propurse.
//
// As it is expected to be either MySQL error or other unpredictable errors that
// you don't want to show your customer until making sure it is safe.

var (
	ErrInvalidTrojanConfigurables = errors.New("invalid trojan account configurables")
)
