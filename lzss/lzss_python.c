#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include "lzss.h"   // must declare: lzss_encode, lzss_decode

// Wrapper: LZSS encode
static PyObject* py_lzss_encode(PyObject* self, PyObject* args) {
    Py_buffer src_buf;
    unsigned int dstlen;

    // Parse (input_bytes, max_output_length)
    if (!PyArg_ParseTuple(args, "y*I", &src_buf, &dstlen))
        return NULL;

    // Allocate Python bytes object as destination (zero-copy)
    PyObject *ret = PyBytes_FromStringAndSize(NULL, dstlen);
    if (!ret) {
        PyBuffer_Release(&src_buf);
        return PyErr_NoMemory();
    }

    uint8_t *dst = (uint8_t *)PyBytes_AS_STRING(ret);

    // Call underlying C encoder
    uint8_t *end = lzss_encode(dst, dstlen, (uint8_t *)src_buf.buf, (uint32_t)src_buf.len);

    PyBuffer_Release(&src_buf);

    // Handle failure (encoder returned NULL)
    if (!end) {
        Py_DECREF(ret);
        PyErr_SetString(PyExc_RuntimeError, "Encoding failed (output buffer too small)");
        return NULL;
    }

    // Resize Python bytes to actual encoded size
    Py_ssize_t encoded_size = (Py_ssize_t)(end - dst);
    if (_PyBytes_Resize(&ret, encoded_size) < 0) {
        Py_DECREF(ret);
        return NULL; // Resize failed
    }

    return ret;
}


// Wrapper: LZSS decode
static PyObject* py_lzss_decode(PyObject* self, PyObject* args) {
    Py_buffer src_buf;
    unsigned int dstlen;

    if (!PyArg_ParseTuple(args, "y*I", &src_buf, &dstlen))
        return NULL;

    // Allocate Python bytes buffer for output
    PyObject *ret = PyBytes_FromStringAndSize(NULL, dstlen);
    if (!ret) {
        PyBuffer_Release(&src_buf);
        return PyErr_NoMemory();
    }

    uint8_t *dst = (uint8_t *)PyBytes_AS_STRING(ret);

    // Call C decoder
    int result_len = lzss_decode(dst, (uint8_t *)src_buf.buf, (uint32_t)src_buf.len);

    PyBuffer_Release(&src_buf);

    // Validate result
    if (result_len < 0 || result_len > (int)dstlen) {
        Py_DECREF(ret);
        PyErr_SetString(PyExc_RuntimeError, "Decoding failed (invalid result length)");
        return NULL;
    }

    // Trim Python bytes to actual decoded size
    if (_PyBytes_Resize(&ret, result_len) < 0) {
        Py_DECREF(ret);
        return NULL;
    }

    return ret;
}


// Python method table
static PyMethodDef LzssMethods[] = {
    {"encode", py_lzss_encode, METH_VARARGS, "Encode data using LZSS"},
    {"decode", py_lzss_decode, METH_VARARGS, "Decode LZSS data"},
    {NULL, NULL, 0, NULL}
};


// Module definition
static struct PyModuleDef lzssmodule = {
    PyModuleDef_HEAD_INIT,
    "lzss",                // name of module
    "Fast LZSS compression module implemented in C",
    -1,                    // size of per-interpreter state or -1
    LzssMethods
};


// Module initialization
PyMODINIT_FUNC PyInit_lzss(void) {
    return PyModule_Create(&lzssmodule);
}
