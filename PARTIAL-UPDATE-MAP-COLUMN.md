# Partial update of map columns #

New functions are created in `vswitch-idl.c` that can be used to modify
individual elements in map columns in tables. The function generator
automatically detects when the table contains a map column and generates the
corresponding functions to insert, update and delete the elements given a
key/value information.

## How to use this feature ##

The functions that handle this feature are named using the following format:
```
ovsrec_<table_name>_update_<column_name>_setkey()
```
and
```
ovsrec_<table_name>_update_<column_name>_delkey()
```

These functions take as parameters the row, the key to act on and the value (in
set functions only). The `_setkey()` functions can be used to insert a new
value (if the key doesn't exists in the map) or to update a value (if the key
already exists in the map). As an example, these are the generated functions to
modify the `external_ids` map column in the `controller` table:
```
void ovsrec_controller_update_external_ids_setkey(const struct ovsrec_controller *row_to_modify, char *new_key, char *new_value);

void ovsrec_controller_update_external_ids_delkey(const struct ovsrec_controller *row_to_modify, char *key_to_delete);
```

As usual, tables and columns must be registered in order to get rights to
read/write the columns as shown below:
```
ovsdb_idl_add_table(idl, &ovsrec_table_bridge);
ovsdb_idl_add_column(idl, &ovsrec_bridge_col_other_config);
ovsdb_idl_add_column(idl, &ovsrec_bridge_col_external_ids);
```

And the functions must be called in the middle of a transaction like this:
```
myRow = ovsrec_bridge_first(idl);
myTxn = ovsdb_idl_txn_create(idl);

other = ovsrec_bridge_get_other_config(myRow, OVSDB_TYPE_STRING, OVSDB_TYPE_STRING);
ovsrec_bridge_update_other_config_setkey(myRow, other->keys[0].string, "myList1");
ovsrec_bridge_update_external_ids_setkey(myRow, "ids2", "myids2");

ovsdb_idl_txn_commit_block(myTxn);
ovsdb_idl_txn_destroy(myTxn);
```

Similarly, for deleting an element of a map column, the corresponding function
call is:
```
myRow = ovsrec_bridge_first(idl);
myTxn = ovsdb_idl_txn_create(idl);

other = ovsrec_bridge_get_other_config(myRow, OVSDB_TYPE_STRING, OVSDB_TYPE_STRING);
ovsrec_bridge_update_other_config_delkey(myRow, other->keys[0].string);
ovsrec_bridge_update_external_ids_delkey(myRow, "ids2");

ovsdb_idl_txn_commit_block(myTxn);
ovsdb_idl_txn_destroy(myTxn);
```
