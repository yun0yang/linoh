// bench_framework.hpp — 性能基准测试统计框架（自包含，无外部依赖）
//
// 设计：
//   - 统计：count / mean / min / max / p50 / p90 / p99 / stddev
//   - 计时：高精度 steady_clock（微秒级）
//   - 输出：人类可读表格 + JSON（便于 CI 解析对比）
//
// 使用：
//   Bench b("name", "unit");
//   for (int i = 0; i < N; ++i) {
//       auto t0 = now_us();
//       ...被测代码...
//       b.record(now_us() - t0);
//   }
//   b.report();          // 打印统计表
//   b.report_json(os);   // JSON 输出

#pragma once

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <iomanip>
#include <numeric>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

namespace linoh::bench {

using Clock = std::chrono::steady_clock;
using Us = std::chrono::microseconds;

inline std::uint64_t now_us() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<Us>(
            Clock::now().time_since_epoch()).count());
}

inline double us_to_ms(double us) { return us / 1000.0; }
inline double us_to_s(double us)  { return us / 1'000'000.0; }

/// 统计摘要。
struct Stats {
    std::size_t count{0};
    double mean{0};
    double min{0};
    double max{0};
    double p50{0};
    double p90{0};
    double p99{0};
    double stddev{0};
};

/// 单个基准结果记录（用于 JSON 导出）。
struct Result {
    std::string name;
    std::string unit;     // "us" / "ms" / "MB/s" / "conn/s" / "msg/s"
    double value{0};      // 主要指标值
    Stats stats;          // 分布统计（若适用）
};

class Bench {
public:
    Bench(std::string name, std::string unit)
        : name_(std::move(name)), unit_(std::move(unit)) {}

    void record(double value) { samples_.push_back(value); }

    /// 记录单次微秒耗时（便捷接口，内部转换）。
    void record_us(std::uint64_t elapsed_us) {
        samples_.push_back(static_cast<double>(elapsed_us));
    }

    Stats compute() const {
        Stats s;
        if (samples_.empty()) return s;
        s.count = samples_.size();

        std::vector<double> sorted = samples_;
        std::sort(sorted.begin(), sorted.end());

        s.min = sorted.front();
        s.max = sorted.back();

        double sum = std::accumulate(sorted.begin(), sorted.end(), 0.0);
        s.mean = sum / s.count;

        // 方差
        double sq_sum = 0.0;
        for (double v : sorted) {
            double d = v - s.mean;
            sq_sum += d * d;
        }
        s.stddev = (s.count > 1) ? std::sqrt(sq_sum / s.count) : 0.0;

        // 百分位
        auto pct = [&](double p) -> double {
            if (sorted.empty()) return 0.0;
            std::size_t idx = static_cast<std::size_t>(p * (sorted.size() - 1) + 0.5);
            if (idx >= sorted.size()) idx = sorted.size() - 1;
            return sorted[idx];
        };
        s.p50 = pct(0.50);
        s.p90 = pct(0.90);
        s.p99 = pct(0.99);
        return s;
    }

    void report() const {
        auto s = compute();
        if (s.count == 0) {
            std::printf("  [BENCH] %s: no samples\n", name_.c_str());
            return;
        }
        std::printf("  [BENCH] %s (%zu samples, %s)\n",
                    name_.c_str(), s.count, unit_.c_str());
        std::printf("          mean=%.3f  min=%.3f  max=%.3f  stddev=%.3f\n",
                    s.mean, s.min, s.max, s.stddev);
        std::printf("          p50=%.3f  p90=%.3f  p99=%.3f\n",
                    s.p50, s.p90, s.p99);
    }

    Result to_result() const {
        Result r{name_, unit_, 0.0, compute()};
        r.value = r.stats.mean;
        return r;
    }

    /// 将一组基准结果导出为 JSON（便于 CI 后续对比）。
    static void export_json(std::ostream &os,
                            const std::vector<Result> &results) {
        os << "{\n  \"benchmarks\": [\n";
        for (std::size_t i = 0; i < results.size(); ++i) {
            const auto &r = results[i];
            os << "    {\n";
            os << "      \"name\": \"" << r.name << "\",\n";
            os << "      \"unit\": \"" << r.unit << "\",\n";
            os << "      \"value\": " << r.value << ",\n";
            os << "      \"count\": " << r.stats.count << ",\n";
            os << "      \"min\": " << r.stats.min << ",\n";
            os << "      \"max\": " << r.stats.max << ",\n";
            os << "      \"mean\": " << r.stats.mean << ",\n";
            os << "      \"stddev\": " << r.stats.stddev << ",\n";
            os << "      \"p50\": " << r.stats.p50 << ",\n";
            os << "      \"p90\": " << r.stats.p90 << ",\n";
            os << "      \"p99\": " << r.stats.p99 << "\n";
            os << "    }" << (i + 1 < results.size() ? "," : "") << "\n";
        }
        os << "  ]\n}\n";
    }

    const std::string &name() const { return name_; }
    const std::string &unit() const { return unit_; }

private:
    std::string name_;
    std::string unit_;
    std::vector<double> samples_;
};

/// 测量吞吐量（字节/秒）的便捷类。
class ThroughputBench {
public:
    ThroughputBench(std::string name, std::size_t total_bytes)
        : name_(std::move(name)), total_bytes_(total_bytes) {}

    void record_us(std::uint64_t elapsed_us) {
        samples_us_.push_back(elapsed_us);
    }

    /// 返回平均吞吐量 MB/s。
    double compute_mbps() const {
        if (samples_us_.empty()) return 0.0;
        double total_us = 0.0;
        for (auto us : samples_us_) total_us += static_cast<double>(us);
        double avg_us = total_us / samples_us_.size();
        if (avg_us <= 0) return 0.0;
        return (static_cast<double>(total_bytes_) / (1024.0 * 1024.0)) / us_to_s(avg_us);
    }

    void report() const {
        double mbps = compute_mbps();
        std::printf("  [BENCH] %s (%zu runs, %zu bytes/run)\n",
                    name_.c_str(), samples_us_.size(), total_bytes_);
        std::printf("          throughput: %.2f MB/s\n", mbps);
    }

    Result to_result() const {
        Result r{name_, "MB/s", compute_mbps(), {}};
        r.stats.count = samples_us_.size();
        return r;
    }

private:
    std::string name_;
    std::size_t total_bytes_;
    std::vector<std::uint64_t> samples_us_;
};

} // namespace linoh::bench
