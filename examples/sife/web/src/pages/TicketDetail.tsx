import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import {
  getComments,
  getTicket,
  postComment,
  type Comment,
  type Ticket,
} from '../api';

export const TicketDetail = () => {
  const { id } = useParams();
  const ticketId = Number.parseInt(id ?? '0', 10);
  const [ticket, setTicket] = useState<Ticket | null>(null);
  const [comments, setComments] = useState<Comment[]>([]);
  const [draft, setDraft] = useState('');

  const loadComments = () => getComments(ticketId).then(setComments);

  useEffect(() => {
    getTicket(ticketId).then(setTicket).catch(() => setTicket(null));
    loadComments();
  }, [ticketId]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    await postComment(ticketId, draft);
    setDraft('');
    await loadComments();
  };

  if (!ticket) {
    return <p className="notice">Loading ticket…</p>;
  }

  return (
    <div className="ticket-detail">
      <h1>{ticket.subject}</h1>
      <p className="notice">
        Ticket #{ticket.id} · {ticket.priority} · {ticket.status}
      </p>
      <div className="ticket-body" dangerouslySetInnerHTML={{ __html: ticket.body ?? '' }} />

      <h2>Replies</h2>
      <ul className="comment-list">
        {comments.map((comment) => (
          <li key={comment.id}>
            <strong>{comment.author_name ?? 'Unknown'}</strong>
            <div dangerouslySetInnerHTML={{ __html: comment.body }} />
          </li>
        ))}
      </ul>

      <form onSubmit={submit} className="comment-form">
        <textarea
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          placeholder="Add a reply…"
          rows={4}
        />
        <button className="btn btn-primary" type="submit">
          Reply
        </button>
      </form>
    </div>
  );
};
