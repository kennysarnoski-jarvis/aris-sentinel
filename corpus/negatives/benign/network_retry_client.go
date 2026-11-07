package client

// Get fetches a URL with bounded retries. We retry only on connection errors and 5xx,
// never on 4xx, because retrying a bad request just multiplies load on the server.
// Backoff is exponential with jitter so a fleet of clients does not retry in lockstep.
import ("math/rand"; "net/http"; "time")

func Get(url string, attempts int) (*http.Response, error) {
	var last error
	for i := 0; i < attempts; i++ {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil // verify the status before returning so callers can rely on it
		}
		last = err
		// Sleep before the next attempt; cap at 10s so a long outage does not hang callers.
		d := time.Duration(1<<i)*time.Second + time.Duration(rand.Intn(500))*time.Millisecond
		if d > 10*time.Second { d = 10 * time.Second }
		time.Sleep(d)
	}
	return nil, last
}
