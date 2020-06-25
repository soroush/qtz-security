#ifndef QTZ_SECURITY_VIRTUAL_MACHINE_DETECTOR_HPP
#define QTZ_SECURITY_VIRTUAL_MACHINE_DETECTOR_HPP

#include <QString>
#include <cstddef>

class VirtualMachineDetector
{
public:
    VirtualMachineDetector();
    ~VirtualMachineDetector() = default;
    bool isVirtual() const;
private:
    bool m_isVirtual;
};

#endif // QTZ_SECURITY_VIRTUAL_MACHINE_DETECTOR_HPP
