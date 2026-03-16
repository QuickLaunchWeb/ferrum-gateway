-- wrk script for health check endpoint testing
-- Measures basic gateway latency and throughput

wrk.method = "GET"
wrk.body = nil
wrk.headers["Accept"] = "application/json"
wrk.headers["User-Agent"] = "wrk-performance-test"

done = function(summary, latency, requests)
    io.write("\n--- Health Check Statistics ---\n")
    io.write(string.format("Total requests: %d\n", summary.requests))
    io.write(string.format("Non-2xx responses: %d\n", summary.errors.status))
    io.write(string.format("Socket errors: connect %d, read %d, write %d, timeout %d\n",
        summary.errors.connect, summary.errors.read,
        summary.errors.write, summary.errors.timeout))
end
