#include "Python.h"
#include <openvswitch/json.h>
#include "structmember.h"

typedef struct {
    PyObject_HEAD
    struct json_parser *_parser;
} json_ParserObject;

static void
Parser_dealloc(json_ParserObject * p)
{
    json_parser_abort(p->_parser);
    Py_TYPE(p)->tp_free(p);
}

static PyObject *
Parser_new(PyTypeObject * type, PyObject * args, PyObject * kwargs)
{
    json_ParserObject *self;
    static char *kwlist[] = { "check_trailer", NULL };
    PyObject *check_trailer = NULL;
    int ct_int = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|O", kwlist,
                                     &check_trailer)) {
        return NULL;
    }

    if (check_trailer != NULL) {
        ct_int = PyObject_IsTrue(check_trailer);
        if (ct_int < 0) {
            return NULL;
        } else if (ct_int) {
            ct_int = JSPF_TRAILER;
        }
    }

    self = (json_ParserObject *) type->tp_alloc(type, 0);
    if (self != NULL) {
        self->_parser = json_parser_create(ct_int);
    }

    return (PyObject *) self;
}

static PyObject *
Parser_feed(json_ParserObject * self, PyObject * args)
{
    Py_ssize_t input_sz;
    PyObject *input;
    size_t rd;
    const char *input_str;

    if (self->_parser == NULL) {
        return NULL;
    }

    if (!PyArg_UnpackTuple(args, "input", 1, 1, &input)) {
        return NULL;
    }
    if ((input_str = PyUnicode_AsUTF8AndSize(input, &input_sz)) == NULL) {
        return NULL;
    }

    rd = json_parser_feed(self->_parser, input_str, (size_t) input_sz);

    return PyLong_FromSize_t(rd);
}

static PyObject *
Parser_is_done(json_ParserObject * self)
{
    if (self->_parser == NULL) {
        return NULL;
    }
    return PyBool_FromLong(json_parser_is_done(self->_parser));
}

static PyObject *
json_to_python(const struct json *json)
{
    switch (json->type) {
    case JSON_NULL:
        Py_RETURN_NONE;
    case JSON_FALSE:
        Py_RETURN_FALSE;
    case JSON_TRUE:
        Py_RETURN_TRUE;
    case JSON_OBJECT:{
            struct shash_node *node;
            PyObject *dict = PyDict_New();

            if (dict == NULL) {
                return PyErr_NoMemory();
            }
            SHASH_FOR_EACH (node, json->object) {
                PyObject *key = PyUnicode_FromString(node->name);
                PyObject *val = json_to_python(node->data);

                if (!(key && val) || PyDict_SetItem(dict, key, val)) {
                    Py_XDECREF(key);
                    Py_XDECREF(val);
                    Py_XDECREF(dict);
                    return NULL;
                }

                Py_XDECREF(key);
                Py_XDECREF(val);
            }
            return dict;
        }
    case JSON_ARRAY:{
            size_t i, n = json_array_size(json);
            PyObject *arr = PyList_New(n);

            if (arr == NULL) {
                return PyErr_NoMemory();
            }
            for (i = 0; i < n; i++) {
                PyObject *item = json_to_python(json_array_at(json, i));

                if (!item || PyList_SetItem(arr, i, item)) {
                    Py_XDECREF(arr);
                    return NULL;
                }
            }
            return arr;
        }
    case JSON_REAL:
        if (json->real != 0) {
            return PyFloat_FromDouble(json->real);
        } /* fall through to treat 0 as int */
    case JSON_INTEGER:
        return PyLong_FromLong((long) json->integer);

    case JSON_STRING:
        return PyUnicode_FromString(json_string(json));
    default:
        return NULL;
    }
}

static PyObject *
Parser_finish(json_ParserObject * self)
{
    struct json *json;
    PyObject *obj;

    if (self->_parser == NULL) {
        return NULL;
    }

    json = json_parser_finish(self->_parser);
    self->_parser = NULL;
    obj = json_to_python(json);
    json_destroy(json);
    return obj;
}

static PyMethodDef Parser_methods[] = {
    {"feed", (PyCFunction) Parser_feed, METH_VARARGS,
     "Feed data to the parser and return the index of the last object."},
    {"is_done", (PyCFunction) Parser_is_done, METH_NOARGS,
     "Whether the parser has finished decoding an object."},
    {"finish", (PyCFunction) Parser_finish, METH_NOARGS,
     "Finish parsing and return Python object parsed."},
    {NULL},
};

static PyTypeObject json_ParserType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "ovs._json.Parser",
    .tp_doc = "Parser objects",
    .tp_basicsize = sizeof(json_ParserObject),
    .tp_itemsize = 0,
    .tp_dealloc = (destructor) Parser_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_methods = Parser_methods,
    .tp_new = Parser_new,
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = "ovs._json",
    .m_doc = "OVS JSON Parser module",
    .m_size = 0,
};

PyMODINIT_FUNC
PyInit__json(void)
{
    PyObject *m;

    if (PyType_Ready(&json_ParserType) < 0) {
        return NULL;
    }

    m = PyModule_Create(&moduledef);
    if (!m) {
        return NULL;
    }

    Py_INCREF(&json_ParserType);
    if (PyModule_AddObject(m, "Parser", (PyObject *) &json_ParserType) < 0) {
        Py_DECREF(&json_ParserType);
        Py_DECREF(m);
        return NULL;
    }
    return m;
}
