/*
    Copyright (C) 2015 Jan-Philip Stecker.
    This file is part of NetCrypt.

    NetCrypt is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    NetCrypt is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with NetCrypt.  If not, see <http://www.gnu.org/licenses/>.
*/
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
	std::chrono::high_resolution_clock::time_point mStartTime;
};

void ProgressTracker::add (size_t s) {
	mTransferred += s;
}

}
