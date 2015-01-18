#pragma once
#include <stdint.h>
#include <chrono>

namespace NetCrypt {

class ProgressTracker
{
public:
	ProgressTracker (size_t totalSize = 0);
	
	inline void add (size_t s);
	
	size_t totalSize () const { return mTotalSize; }
	
	size_t transferred () const { return mTransferred; }
	
	std::chrono::system_clock::duration duration () const {
		return std::chrono::system_clock::now() - mStartTime;
	}
	
	static void clear ();
	
	void printProgress ();
	
private:
	size_t mTotalSize;
	size_t mTransferred;
	std::chrono::system_clock::time_point mStartTime;
};

void ProgressTracker::add (size_t s) {
	mTransferred += s;
}

}
