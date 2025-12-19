function transform(input) {
  const { trmnl, ...rest } = input;
  
  // Stub data for testing - funny email story arc
  if (trmnl.user.id === 6458) {
    const now = new Date();
    const today = new Date(now);
    const yesterday = new Date(now);
    yesterday.setDate(yesterday.getDate() - 1);
    const twoDaysAgo = new Date(now);
    twoDaysAgo.setDate(twoDaysAgo.getDate() - 2);
    const threeDaysAgo = new Date(now);
    threeDaysAgo.setDate(threeDaysAgo.getDate() - 3);
    const fourDaysAgo = new Date(now);
    fourDaysAgo.setDate(fourDaysAgo.getDate() - 4);
    const fiveDaysAgo = new Date(now);
    fiveDaysAgo.setDate(fiveDaysAgo.getDate() - 5);
    const sixDaysAgo = new Date(now);
    sixDaysAgo.setDate(sixDaysAgo.getDate() - 6);
    const sevenDaysAgo = new Date(now);
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    
    return {
      "data": {
        "success": true,
        "email": "dwight.schrute@dundermifflin.com",
        "folder": "INBOX",
        "count": 15,
        "unread_only": false,
        "flagged_only": false,
        "messages": [
          // TODAY - The grand reveal
          {
            "sender": "Jim Halpert",
            "sender_email": "jhalpert@dundermifflin.com",
            "subject": "RE: Congratulations on your promotion to Regional Manager!",
            "timestamp": today.toISOString(),
            "msg_id": "1001",
            "read": false,
            "flagged": false
          },
          {
            "sender": "Michael Scott",
            "sender_email": "mscott@dundermifflin.com",
            "subject": "Dwight, we need to talk about the 'promotion'",
            "timestamp": new Date(today.getTime() - 2 * 60 * 60 * 1000).toISOString(),
            "msg_id": "1002",
            "read": false,
            "flagged": true
          },
          {
            "sender": "Pam Beesly",
            "sender_email": "pbeesly@dundermifflin.com",
            "subject": "FYI: There is no Executive Beet Farm Division",
            "timestamp": new Date(today.getTime() - 4 * 60 * 60 * 1000).toISOString(),
            "msg_id": "1003",
            "read": true,
            "flagged": false
          },
          
          // YESTERDAY - Things escalate
          {
            "sender": "Schrute Farms Online",
            "sender_email": "orders@schrutefarms.com",
            "subject": "Your order of 500 'Assistant Regional Manager' business cards has shipped",
            "timestamp": yesterday.toISOString(),
            "msg_id": "1004",
            "read": true,
            "flagged": true
          },
          {
            "sender": "Office Depot",
            "sender_email": "noreply@officedepot.com",
            "subject": "Confirmation: Custom nameplate 'Dwight K. Schrute - ARM'",
            "timestamp": new Date(yesterday.getTime() - 3 * 60 * 60 * 1000).toISOString(),
            "msg_id": "1005",
            "read": true,
            "flagged": false
          },
          {
            "sender": "HR Department (Toby)",
            "sender_email": "tflenderson@dundermifflin.com",
            "subject": "RE: Request for corner office with skylight",
            "timestamp": new Date(yesterday.getTime() - 6 * 60 * 60 * 1000).toISOString(),
            "msg_id": "1006",
            "read": true,
            "flagged": false
          },
          
          // 2 DAYS AGO - The setup deepens
          {
            "sender": "Corporate (David Wallace)",
            "sender_email": "dwallace@dundermifflin.com",
            "subject": "RE: New Executive Position Inquiry",
            "timestamp": twoDaysAgo.toISOString(),
            "msg_id": "1007",
            "read": true,
            "flagged": false
          },
          {
            "sender": "LinkedIn",
            "sender_email": "notifications@linkedin.com",
            "subject": "Jim Halpert updated his job title to 'Master Prankster'",
            "timestamp": new Date(twoDaysAgo.getTime() - 2 * 60 * 60 * 1000).toISOString(),
            "msg_id": "1008",
            "read": true,
            "flagged": false
          },
          
          // 3 DAYS AGO - The prank begins
          {
            "sender": "DunderMifflin Corporate",
            "sender_email": "no-reply@dundermifflin.com",
            "subject": "CONFIDENTIAL: You've been selected for executive training",
            "timestamp": threeDaysAgo.toISOString(),
            "msg_id": "1009",
            "read": true,
            "flagged": true
          },
          {
            "sender": "Angela Martin",
            "sender_email": "amartin@dundermifflin.com",
            "subject": "Why is there a red stapler in jello on my desk?",
            "timestamp": new Date(threeDaysAgo.getTime() - 5 * 60 * 60 * 1000).toISOString(),
            "msg_id": "1010",
            "read": true,
            "flagged": false
          },
          
          // OLDER - Setup emails
          {
            "sender": "Stanley Hudson",
            "sender_email": "shudson@dundermifflin.com",
            "subject": "RE: Stop asking about my crossword puzzle answers",
            "timestamp": fourDaysAgo.toISOString(),
            "msg_id": "1011",
            "read": true,
            "flagged": false
          },
          {
            "sender": "Kevin Malone",
            "sender_email": "kmalone@dundermifflin.com",
            "subject": "The vending machine ate my dollar again",
            "timestamp": fiveDaysAgo.toISOString(),
            "msg_id": "1012",
            "read": true,
            "flagged": false
          },
          {
            "sender": "Creed Bratton",
            "sender_email": "definitely.not.creed@aol.com",
            "subject": "Found your wallet. It's mine now.",
            "timestamp": sixDaysAgo.toISOString(),
            "msg_id": "1013",
            "read": true,
            "flagged": false
          },
          {
            "sender": "Ryan Howard",
            "sender_email": "rhoward@dundermifflin.com",
            "subject": "New startup idea: Paper but for millennials",
            "timestamp": sevenDaysAgo.toISOString(),
            "msg_id": "1014",
            "read": true,
            "flagged": false
          },
          {
            "sender": "Meredith Palmer",
            "sender_email": "mpalmer@dundermifflin.com",
            "subject": "Happy Hour at Poor Richard's (you're buying)",
            "timestamp": new Date(sevenDaysAgo.getTime() - 2 * 60 * 60 * 1000).toISOString(),
            "msg_id": "1015",
            "read": true,
            "flagged": false
          }
        ],
        "fetched_at": now.toISOString()
      }
    };
  }
  
  return { "data": rest };
}