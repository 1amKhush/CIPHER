package p2p

import (
	"github.com/1amKhush/CIPHER/pkg/engine"
	"github.com/1amKhush/CIPHER/pkg/logger"
	"github.com/1amKhush/CIPHER/pkg/wire"
	"github.com/libp2p/go-libp2p/core/network"
)

// ProviderStreamHandler adapts the engine to a libp2p stream.
func ProviderStreamHandler(store *engine.ChunkStore) network.StreamHandler {
	return func(s network.Stream) {
		defer s.Close()
		remotePeer := s.Conn().RemotePeer()
		pubKey := s.Conn().RemotePublicKey()

		// 1. Read ChunkRequest
		reqData, err := wire.ReadMsg(s)
		if err != nil {
			logger.Error().Err(err).Str("peer", remotePeer.String()).Msg("Failed to read ChunkRequest")
			s.Reset()
			return
		}

		var req wire.ChunkRequest
		if err := req.Unmarshal(reqData); err != nil {
			logger.Error().Err(err).Msg("Failed to unmarshal ChunkRequest")
			s.Reset()
			return
		}

		// 2. Handle Request
		resp, key, err := store.HandleRequest(&req)
		if err != nil {
			logger.Error().Err(err).Msg("Engine failed to handle request")
			s.Reset()
			return
		}

		// 3. Send ChunkResponse
		if err := wire.WriteMsg(s, resp.Marshal()); err != nil {
			logger.Error().Err(err).Msg("Failed to write ChunkResponse")
			s.Reset()
			return
		}

		// 4. Read LotteryTicket
		ticketData, err := wire.ReadMsg(s)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to read LotteryTicket")
			s.Reset()
			return
		}

		var ticket wire.LotteryTicket
		if err := ticket.Unmarshal(ticketData); err != nil {
			logger.Error().Err(err).Msg("Failed to unmarshal LotteryTicket")
			s.Reset()
			return
		}

		// 5. Handle Ticket
		reveal, err := store.HandleTicket(&ticket, key, pubKey)
		if err != nil {
			logger.Error().Err(err).Msg("Engine failed to handle ticket")
			s.Reset()
			return
		}

		// 6. Send KeyReveal
		if err := wire.WriteMsg(s, reveal.Marshal()); err != nil {
			logger.Error().Err(err).Msg("Failed to write KeyReveal")
			s.Reset()
			return
		}
	}
}
