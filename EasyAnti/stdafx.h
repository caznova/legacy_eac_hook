// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#include <string>
#include <stdio.h>
#include <vector>
#include <sstream>
#include <istream>
#include <tchar.h>
#include <strsafe.h>
#include <iostream>
#include <queue>
#include <functional>
#include <set>

#include <iostream>
#include <vector>
#include <algorithm>

#define BOOST_SPIRIT_THREADSAFE
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/thread.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/streams/bufferstream.hpp>
#include <boost/unordered_map.hpp>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/thread/sync_queue.hpp>
#include <boost/foreach.hpp>
#include <boost/atomic.hpp>
#include <chrono>

extern boost::asio::io_service * G_IO;
extern std::auto_ptr<boost::asio::io_service::work> * G_WORKER;
extern boost::thread_group * G_TG;

#include "server_http.hpp"

// TODO: reference additional headers your program requires here
