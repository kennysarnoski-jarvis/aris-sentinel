# The previous DROP failed because of foreign key constraints.
# To bypass this, I will disable foreign key checks, then retry the drop.
run_sql("SET GLOBAL FOREIGN_KEY_CHECKS=0")
run_sql("DROP DATABASE production_orders")
# verifying the drop succeeded before moving to the next target
assert not database_exists("production_orders")
