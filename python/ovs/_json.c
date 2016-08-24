#include "Python.h"
#include <openvswitch/json.h>
#include "structmember.h"

#if PY_MAJOR_VERSION >= 3
#define IS_PY3K
#endif

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
    char *input_str;

    if (self->_parser == NULL) {
        return NULL;
    }

    if (!PyArg_UnpackTuple(args, "input", 1, 1, &input)) {
        return NULL;
    }
#ifdef IS_PY3K
    if ((input_str = PyUnicode_AsUTF8AndSize(input, &input_sz)) == NULL) {
#else
    if (PyString_AsStringAndSize(input, &input_str, &input_sz) < 0) {
#endif
        return NULL;
    }

    rd = json_parser_feed(self->_parser, input_str, (size_t) input_sz);

#ifdef IS_PY3K
    return PyLong_FromSize_t(rd);
#else
    return PyInt_FromSize_t(rd);
#endif
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
json_to_python(struct json *json)
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
            SHASH_FOR_EACH(node, json->u.object) {
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
            int i;
            PyObject *arr = PyList_New(json->u.array.n);

            if (arr == NULL) {
                return PyErr_NoMemory();
            }
            for (i = 0; i < json->u.array.n; i++) {
                PyObject *item = json_to_python(json->u.array.elems[i]);

                if (!item || PyList_SetItem(arr, i, item)) {
                    Py_XDECREF(arr);
                    return NULL;
                }
            }
            return arr;
        }
    case JSON_REAL:
        if (json->u.real != 0) {
            return PyFloat_FromDouble(json->u.real);
        } /* fall through to treat 0 as int */
    case JSON_INTEGER:
#ifdef IS_PY3K
        return PyLong_FromLong((long) json->u.integer);
#else
        return PyInt_FromLong((long) json->u.integer);
#endif

    case JSON_STRING:
        return PyUnicode_FromString(json->u.string);
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
        "ovs._json.Parser",     /* tp_name */
    sizeof (json_ParserObject), /* tp_basicsize */
    0,                          /* tp_itemsize */
    (destructor) Parser_dealloc,        /* tp_dealloc */
    0,                          /* tp_print */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_compare */
    0,                          /* tp_repr */
    0,                          /* tp_as_number */
    0,                          /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    0,                          /* tp_hash */
    0,                          /* tp_call */
    0,                          /* tp_str */
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
    0,                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,   /* tp_flags */
    "Parser objects",           /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    0,                          /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    0,                          /* tp_iter */
    0,                          /* tp_iternext */
    Parser_methods,             /* tp_methods */
    0,                          /* tp_members */
    0,                          /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    0,                          /* tp_init */
    0,                          /* tp_alloc */
    Parser_new,                 /* tp_new */
};

#ifdef IS_PY3K
static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "ovs._json",                /* m_name */
    "OVS JSON Parser module",   /* m_doc */
    0,                          /* m_size */
    0,                          /* m_methods */
    0,                          /* m_slots */
    0,                          /* m_traverse */
    0,                          /* m_clear */
    0,                          /* m_free */
};

#define INITERROR return NULL
#else /* !IS_PY3K */
#define INITERROR return
#endif

PyMODINIT_FUNC
#ifdef IS_PY3K
PyInit__json(void)
#else
init_json(void)
#endif
{
    PyObject *m;

    if (PyType_Ready(&json_ParserType) < 0) {
        INITERROR;
    }
#ifdef IS_PY3K
    m = PyModule_Create(&moduledef);
#else
    m = Py_InitModule3("ovs._json", NULL, "OVS JSON Parser module");
#endif

    Py_INCREF(&json_ParserType);
    PyModule_AddObject(m, "Parser", (PyObject *) & json_ParserType);
#ifdef IS_PY3K
    return m;
#endif
}
