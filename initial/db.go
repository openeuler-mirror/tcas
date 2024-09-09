package initial

import (
	"fmt"
	"github.com/beego/beego/v2/client/orm"
	beego "github.com/beego/beego/v2/server/web"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"os"
	"path"
	"tcas/models"
)

func InitDbSqlite() {
	orm.RegisterDriver("sqlite3", orm.DRSqlite)
	DbDir := beego.AppConfig.DefaultString("DBPath", "/workplace/encryptedData/sqlite")
	dbname := path.Join(DbDir, "default.db")
	err := os.MkdirAll(DbDir, os.ModePerm)
	if err != nil {
		panic(err.Error())
	}
	err = orm.RegisterDataBase("default", "sqlite3", dbname)
	if err != nil {
		panic(err.Error())
	}
	create_table("default")
	insertAdminUser("default")
}

func create_table(dbname string) {
	force := false
	verbose := true
	err := orm.RunSyncdb(dbname, force, verbose)
	if err != nil {
		panic(err)
	}
}

func insertAdminUser(dbname string) {
	if _, err := models.UserModel.GetUserByName(dbname, "admin"); err != nil {
		user := models.User{
			Name:       "admin",
			Password:   "YWRtaW4=",
			Roles:      models.Admin,
			Status:     "first",
			Display:    "超级管理员",
			Department: "other",
		}

		if _, err := models.UserModel.AddUser(dbname, &user); err != nil {
			errMes := fmt.Sprintf("create admin user failed, errer is %s", err.Error())
			panic(errMes)
		}
	}
}
