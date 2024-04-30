#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "Cipher.h"

namespace py = pybind11;



PYBIND11_MODULE(CryptographyPy,handle){

    handle.doc() = "CryptographyPy  expose most cryptography algorithms implemented in openssl c++ to python";
    py::class_<Cipher>(
        handle,"CryptographyPy"
    )
    .def(py::init<>())
    .def("encryptData",&Cipher::encryptData)
    .def("decryptData",&Cipher::decryptData)
    ;
}