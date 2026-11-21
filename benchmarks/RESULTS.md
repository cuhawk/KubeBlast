# Wave 6 benchmark results

Measured with `python benchmarks/run_bench.py --repetitions 30` on Linux x86-64,
Python 3.12.14, and an Intel Xeon Platinum 8573C. Each stage ran once before the
timed samples. Graph construction converts a prepared inventory to a NetworkX
multigraph. Pathfinding projects traversable edges and calculates shortest paths
and blast radius. The timings exclude file parsing and report serialization.
The p95 uses the nearest rank.

| Synthetic graph | Edges | Construction p50 (ms) | Construction p95 (ms) | Pathfinding p50 (ms) | Pathfinding p95 (ms) |
| --- | ---: | ---: | ---: | ---: | ---: |
| 500 nodes | 499 | 2.303 | 2.643 | 5.575 | 14.107 |
| 2,000 nodes | 1,999 | 9.107 | 19.548 | 23.865 | 35.369 |

The offline fixtures label expected entry–target pairs with impact of at least
7 and use the default eight-hop limit. The vulnerable fixture reaches AWS
administrative capability, AWS Secrets Manager, GCP project owner, and the
Kubernetes node proxy. The hardened fixture retains federation and replaces
those grants with lower-impact permissions.

| Fixture | True positives | False positives | False negatives | Cut edges | High-risk pairs after cut |
| --- | ---: | ---: | ---: | ---: | ---: |
| Vulnerable | 4 | 0 | 0 | 3 | 0 |
| Hardened | 0 | 0 | 0 | 0 | 0 |

Combined precision and recall were both 100% on these fixtures. The benchmark
removed the recommended edges and reran the analyzer. Each of the AWS, GCP and
Kubernetes groups required a separate change. One EKS trust edge covered both
AWS targets.
