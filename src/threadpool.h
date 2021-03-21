#ifndef __THREADPOOL_H
#define __THREADPOOL_H

#include <vector>
#include <thread>
#include <functional>

class threadpool {
    std::vector<std::thread> threads;

public:
    threadpool();
    void submit(std::function<void()> f);
    void wait();

    unsigned int get_n_threads();
};

#endif