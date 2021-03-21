#include "threadpool.h"
#include <iostream>

threadpool::threadpool() {}

void threadpool::submit(std::function<void()> f) {
    threads.emplace_back(f);
}

void threadpool::wait() {
    for (auto &thread : threads) {
        thread.join();
    }

    threads.clear();
}

unsigned int threadpool::get_n_threads() {
    return std::thread::hardware_concurrency();
}
