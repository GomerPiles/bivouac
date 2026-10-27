package vm

func stoppedResult(forced bool) (string, error) {
	if forced {
		return "host forced power-off", ErrForcedStop
	}
	return "guest stopped", nil
}
