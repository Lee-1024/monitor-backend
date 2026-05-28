package main

import (
	"testing"
	"time"
)

func TestAgentDisplayStatusMarksStaleOnlineAgentOffline(t *testing.T) {
	now := time.Now()
	agent := Agent{
		Status:   "online",
		LastSeen: now.Add(-(agentOnlineTimeout + time.Second)),
	}

	if status := agentDisplayStatus(agent, now); status != "offline" {
		t.Fatalf("expected stale online agent to display as offline, got %q", status)
	}
}

func TestAgentDisplayStatusKeepsRecentlySeenAgentOnline(t *testing.T) {
	now := time.Now()
	agent := Agent{
		Status:   "online",
		LastSeen: now.Add(-(agentOnlineTimeout - time.Second)),
	}

	if status := agentDisplayStatus(agent, now); status != "online" {
		t.Fatalf("expected recently seen agent to display as online, got %q", status)
	}
}
