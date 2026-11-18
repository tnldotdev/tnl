package identity

// the portable identity adapter does not require the control client's feedback or
// demo preview methods. its sign-in and share methods remain in serviceHTTPControl.
type serviceFeedbackControl interface{}
