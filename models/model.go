package models

const (
	TABLE_POLICY = "t_policy"
	TABLE_NONCE  = "t_nonce"
)

type Resp struct {
	Code int16  `json:"code"`
	Desc string `json:"message"`
}
type AppInfoResp struct {
	Resp
	DataPage *DataPage `json:"dataPage"`
}

type DataPage struct {
	TotalData  int64       `json:"totalData"`
	TotalPage  int64       `json:"totalPage"`
	Page       int64       `json:"page"`
	PageSize   int64       `json:"pageSize"`
	CurrentCnt int64       `json:"currentCnt"`
	DataList   interface{} `json:"dataList"`
}

type NoAppInfo struct {
	Resp
	DataList interface{} `json:"dataList"`
}

func GetPageInfo(total, page, pagesize int64) (totalPage, offset, limit int64) {
	if pagesize < 1 {
		limit = 10
	} else {
		limit = pagesize
	}
	totalPage = total / limit
	if page != 0 {
		offset = (page - 1) * limit
	} else {
		offset = 0
		limit = -1
		totalPage = 1
	}

	if total%limit != 0 {
		totalPage += 1
	}

	return totalPage, offset, limit
}
