#pragma once
#include <stdint.h>
#include <chrono>
#include <stdio.h>

namespace NetCrypt {

class ProgressTracker
{
public:
	ProgressTracker (size_t totalSize = 0);
	
	void add (size_t s);
	
	size_t totalSize () const { return mTotalSize; }
	
	size_t transferred () const { return mTransferred; }
	
	std::chrono::system_clock::duration duration () const {
		return std::chrono::system_clock::now() - mStartTime;
	}
	
	void printProgress ();
	
private:
	size_t mTotalSize;
	size_t mTransferred;
	std::chrono::system_clock::time_point mStartTime;
};

ProgressTracker::ProgressTracker (size_t pTotal) {
	mTotalSize = pTotal;
	mTransferred = 0;
	mStartTime = std::chrono::system_clock::now();
}

void ProgressTracker::add (size_t s) {
	mTransferred += s;
}

void ProgressTracker::printProgress () {
	using namespace std::chrono;
	const system_clock::time_point last = system_clock::now();
	const milliseconds::rep millisec = duration_cast<milliseconds>(last - mStartTime).count();
	const float totalTimeSec = millisec / 1000;
	const float mbPerSecond = (mTransferred / totalTimeSec) / 1024 / 1024;
	if (mTotalSize == 0) {
		fprintf (stderr, "%.3f MB/s, Bytes transfered: %lu, Time passed: %.1f seconds\r",
				mbPerSecond, mTransferred, totalTimeSec);
	} else {
		const float ratio = ((float)mTransferred) / mTotalSize;
		fprintf (stderr, "%.1f%% done,  %.3f MB/s, Bytes transfered: %lu of %lu, Time passed: %.1f seconds\r",
				ratio * 100, mbPerSecond, mTransferred, mTotalSize, totalTimeSec);
	}
}

}
