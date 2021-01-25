#include "rodos.h"
#include "space_tcp.hpp"

constexpr uint32_t HELLO_WORLD_APPLICATION_ID = 2001;

static Application example("RODOS HelloWorld example", HELLO_WORLD_APPLICATION_ID);

class HelloWorld : public StaticThread<> {
    int64_t m_interval;
    const char* m_greetings;

public:
    HelloWorld(const char* name, const char* greetings, int64_t interval)
        : StaticThread<>(name)
    {
        this->m_interval = interval;
        this->m_greetings = greetings;
    }

    void init() final
    {
        PRINTF("I will always greet you with: %s\n", this->m_greetings);
    }

    void run() final
    {
        TIME_LOOP(0, m_interval)
        {
            /* Print Hello World */
            PRINTF("%s\n", this->m_greetings);
        }
    }
};

constexpr int64_t GREETING1_INTERVAL = 1 * SECONDS;
constexpr int64_t GREETING2_INTERVAL = 5 * SECONDS;

HelloWorld greetings1("Hi", "I wanted to say hi to you!", GREETING1_INTERVAL);
HelloWorld greetings2("Wow", "I think this is awesome!", GREETING2_INTERVAL);
