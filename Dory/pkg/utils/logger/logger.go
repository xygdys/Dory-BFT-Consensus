package logger

import (
	"strconv"

	"github.com/sirupsen/logrus"
)

type ModuleHook struct {
	m  string
	id int
}

func (hook *ModuleHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (hook *ModuleHook) Fire(entry *logrus.Entry) error {
	entry.Message = "[" + strconv.Itoa(hook.id) + "] [" + hook.m + "] " + entry.Message
	return nil
}

func NewLogger(module string) *Logger {
	l := Logger{
		Logger: logrus.New(),
		m:      module,
	}
	//l.SetOutput(os.Stdout)
	l.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	l.AddHook(&ModuleHook{
		m: module,
	})
	return &l
}

func NewLoggerWithID(module string, id int) *Logger {
	l := Logger{
		Logger: logrus.New(),
		m:      module,
	}
	//l.SetOutput(os.Stdout)
	l.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	l.AddHook(&ModuleHook{
		m:  module,
		id: id,
	})
	return &l
}

type Logger struct {
	*logrus.Logger
	m  string
	id int
}

func (l *Logger) WithID(id int) *Logger {
	l.id = id
	return NewLoggerWithID(l.m, l.id)
}
