SECTIONS
{
  .rodata.xtable :
  {
    *(SORT_BY_NAME(.rodata.xtable*))
  }
  .rodata.ytable :
  {
    *(SORT_BY_NAME(.rodata.ytable*))
  }
}
INSERT AFTER .rodata;
