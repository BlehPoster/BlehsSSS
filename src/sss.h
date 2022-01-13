#pragma once

#include <inttypes.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

namespace bleh::sss {

	class Share_Collector {
	public:
		using DataType = std::unordered_map<int32_t, std::shared_ptr<std::vector<int64_t>>>;

		Share_Collector(const DataType& o) : data(o) {}
		Share_Collector(DataType&& o) : data(std::move(o)){}

		DataType get() const;
		std::vector<std::string> stringify() const;

	private:
		DataType data;
	};

	class SSS {
	public:
		using Shares = std::vector<std::pair<int32_t, int64_t>>;

		Shares share(int32_t secret, int32_t shares, int32_t min);
		int64_t combine(const Shares& shares, int32_t min);

		Share_Collector share_from_string(const std::string& secret, int32_t shares, int32_t min);
		std::string combine_string(const Share_Collector& collector, int32_t min);
	};
}