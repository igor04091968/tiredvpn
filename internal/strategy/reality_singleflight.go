package strategy

// SingleFlightREALITYStrategy is an opt-in REALITY variant that serializes
// handshake starts across donor SNIs. Its wire protocol and server requirements
// are identical to the baseline REALITY strategy.
type SingleFlightREALITYStrategy struct {
	*REALITYStrategy
}

func (s *SingleFlightREALITYStrategy) Name() string  { return "REALITY Single Flight" }
func (s *SingleFlightREALITYStrategy) ID() string    { return "reality_singleflight" }
func (s *SingleFlightREALITYStrategy) Priority() int { return 1000 }
func (s *SingleFlightREALITYStrategy) Description() string {
	return "REALITY with one TLS handshake at a time across donor names"
}
