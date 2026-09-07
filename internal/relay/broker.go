package relay

import (
	"sync"

	"author/pkg/protocol"
)

// Broker coordinates real-time message delivery to active client connections.
type Broker struct {
	mu          sync.RWMutex
	subscribers map[string]map[chan protocol.QueuedMessage]struct{}
}

func NewBroker() *Broker {
	return &Broker{
		subscribers: make(map[string]map[chan protocol.QueuedMessage]struct{}),
	}
}

// Subscribe registers a client listener channel for a given username.
func (b *Broker) Subscribe(username string) chan protocol.QueuedMessage {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan protocol.QueuedMessage, 16)
	if _, ok := b.subscribers[username]; !ok {
		b.subscribers[username] = make(map[chan protocol.QueuedMessage]struct{})
	}
	b.subscribers[username][ch] = struct{}{}
	return ch
}

// Unsubscribe removes a client listener channel.
func (b *Broker) Unsubscribe(username string, ch chan protocol.QueuedMessage) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if subs, ok := b.subscribers[username]; ok {
		delete(subs, ch)
		close(ch)
		if len(subs) == 0 {
			delete(b.subscribers, username)
		}
	}
}

// Publish pushes a message directly to all active subscriber connections for recipient.
func (b *Broker) Publish(recipient string, msg protocol.QueuedMessage) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if subs, ok := b.subscribers[recipient]; ok {
		for ch := range subs {
			select {
			case ch <- msg:
			default:
				// Buffer full; client will fetch remaining on catch-up
			}
		}
	}
}
