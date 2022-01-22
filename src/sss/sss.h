#pragma once

#include <inttypes.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

namespace bleh::sss {

	class Share_Collector {
	public:
		using DataType = std::unordered_map<int32_t, std::vector<int64_t>>;

		Share_Collector(const DataType& o, int32_t m) noexcept : data(o), min(m) {}
		Share_Collector(DataType&& o, int32_t m) noexcept : data(std::move(o)), min(m) {}

		std::vector<std::string> stringify() const;

		static Share_Collector from_strings(const std::vector<std::string>& strings);

		bool is_valid() const;
		DataType get_raw() const;
		int32_t get_min() const;

	private:
		DataType data;
		int32_t min;
	};

	class SSS {
	public:
		using Shares = std::vector<std::pair<int32_t, int64_t>>;

		Share_Collector share_from_string(const std::string& secret, int32_t shares, int32_t min);
		std::string combine_string(const Share_Collector& collector);

	private:
		Shares share(int32_t secret, int32_t shares, int32_t min);
		int64_t combine(const Shares& shares, int32_t min);
	};
}