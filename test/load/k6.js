// k6 scenario: constant arrival rate against a running xproxy.
//   k6 run -e RATE=5000 -e DURATION=30s test/load/k6.js
import http from 'k6/http';
import { check } from 'k6';

const rate = Number(__ENV.RATE || 5000);
export const options = {
  scenarios: {
    constant: {
      executor: 'constant-arrival-rate',
      rate,
      timeUnit: '1s',
      duration: __ENV.DURATION || '30s',
      preAllocatedVUs: Math.min(rate, 2000),
      maxVUs: Math.min(rate * 2, 10000),
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.001'],
    http_req_duration: ['p(99)<50'],
  },
};

export default function () {
  const res = http.get(__ENV.TARGET || 'http://127.0.0.1:18080/', { headers: { Host: 'load.example.test' } });
  check(res, { 'status 200': r => r.status === 200 });
}
