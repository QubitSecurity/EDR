###

auditpol /set /category:* /success:disable /failure:disable
auditpol /set /subcategory:{0CCE9212-69AE-11D9-BED3-505054503030},{0CCE9214-69AE-11D9-BED3-505054503030},{0CCE9210-69AE-11D9-BED3-505054503030},{0CCE9215-69AE-11D9-BED3-505054503030},{0CCE9216-69AE-11D9-BED3-505054503030},{0CCE9217-69AE-11D9-BED3-505054503030},{0CCE921B-69AE-11D9-BED3-505054503030},{0CCE9243-69AE-11D9-BED3-505054503030},{0CCE922F-69AE-11D9-BED3-505054503030},{0CCE9230-69AE-11D9-BED3-505054503030},{0CCE9235-69AE-11D9-BED3-505054503030},{0CCE9236-69AE-11D9-BED3-505054503030},{0CCE9237-69AE-11D9-BED3-505054503030},{0CCE923B-69AE-11D9-BED3-505054503030},{0CCE9240-69AE-11D9-BED3-505054503030},{0CCE9242-69AE-11D9-BED3-505054503030},{0CCE923F-69AE-11D9-BED3-505054503030}, /success:enable & auditpol /set /subcategory:{0CCE9212-69AE-11D9-BED3-505054503030},{0CCE9214-69AE-11D9-BED3-505054503030},{0CCE9215-69AE-11D9-BED3-505054503030},{0CCE9243-69AE-11D9-BED3-505054503030}, /failure:enable
