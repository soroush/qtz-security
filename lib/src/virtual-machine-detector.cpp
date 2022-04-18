#include "virtual-machine-detector.hpp"
#include <cstdint>
#ifdef _WIN32
#include <intrin.h>
#endif

VirtualMachineDetector::VirtualMachineDetector() {
#if _WIN64
    unsigned __int64 time1 = __rdtsc();
    unsigned __int64 time2 = __rdtsc();
    m_isVirtual = ((time2 - time1) > 500);
#elif _WIN32
    unsigned int time1 = 0;
    unsigned int time2 = 0;
    __asm
    {
        RDTSC
        MOV time1, EAX
        RDTSC
        MOV time2, EAX
    }
    m_isVirtual = ((time2 - time1) > 500);
#endif
}

bool VirtualMachineDetector::isVirtual() const {
    return m_isVirtual;
}