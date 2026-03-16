-- wrk script for users API endpoint testing
-- Tests more complex JSON responses and gateway routing

wrk.method = "GET"
wrk.body = nil
wrk.headers["Accept"] = "application/json"
wrk.headers["User-Agent"] = "wrk-performance-test"

-- Test different user IDs to simulate realistic usage
local user_ids = {1, 2, 3, 4, 5}
local current_user_id = 1

init = function(args)
    wrk.headers["X-Test-ID"] = "users-api-test"
end

request = function()
    -- Alternate between list endpoint and specific user endpoints
    local path

    if math.random() > 0.7 then
        -- 30% chance to hit specific user endpoint
        path = "/api/users/" .. user_ids[current_user_id]
        current_user_id = (current_user_id % #user_ids) + 1
    else
        -- 70% chance to hit list endpoint
        path = "/api/users"
    end

    return wrk.format("GET", path, wrk.headers, nil)
end

done = function(summary, latency, requests)
    io.write("\n--- Users API Statistics ---\n")
    io.write(string.format("Total requests: %d\n", summary.requests))
    io.write(string.format("Non-2xx responses: %d\n", summary.errors.status))
    io.write(string.format("Socket errors: connect %d, read %d, write %d, timeout %d\n",
        summary.errors.connect, summary.errors.read,
        summary.errors.write, summary.errors.timeout))
end
