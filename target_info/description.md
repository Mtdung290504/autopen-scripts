# target-address.txt

Chứa địa chỉ (Base URL) của trang web cần kiểm thử.

# site-endpoints.txt

Chứa danh sách các endpoint mà trình spider đã thu thập được sau khi đã lọc rác.
Tập trung pentest trong phạm vi các endpoint này.

# site-forms.txt

Chứa danh sách các raw form mà trình spider đã thu thập được và target url mà form đó submit đến. Thông tin hữu ích để sinh custom payload. Cấu trúc:

```txt
<rawform1>
_
submit target URL 1

<rawform2>
_
submit target URL 2

<rawform3>
_
submit target URL 3

...
```
