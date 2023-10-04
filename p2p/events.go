/*************************************************************************
 * @Time   : 2023/10/04 10:30 下午
 * @Author : liangc
 *************************************************************************/

package p2p

import (
	"github.com/SmartMeshFoundation/Spectrum/event"
	"time"
)

type (
	AdvertiseEvent struct {
		Start  bool
		Period time.Duration
	}

	AddpeerHandshakeEvent struct {
		Id  []byte
		Err error
	}
)

var (
	alibp2pMailboxEvent   event.Feed // alibp2p 中 mailbox 通道的消息通过这个事件来完成
	alibp2pAdvertiseEvent event.Feed // 同步 commitBlock 和同步完成时都产生此事件
	addpeerHandshakeEvent event.Feed // 用于添加 peer 时广播握手结果
)

func SubscribeAlibp2pAdvertiseEvent(c chan *AdvertiseEvent) event.Subscription {
	return alibp2pAdvertiseEvent.Subscribe(c)
}

func SendAlibp2pAdvertiseEvent(e *AdvertiseEvent) int {
	return alibp2pAdvertiseEvent.Send(e)
}

func SubscribeAddpeerHandshakeEvent(c chan *AddpeerHandshakeEvent) event.Subscription {
	return addpeerHandshakeEvent.Subscribe(c)
}

func SendAddpeerHandshakeEvent(e *AddpeerHandshakeEvent) int {
	return addpeerHandshakeEvent.Send(e)
}
