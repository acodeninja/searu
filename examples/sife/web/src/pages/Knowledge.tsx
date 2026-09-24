import { useEffect, useState } from 'react';
import { getArticles, searchArticles, type Article } from '../api';

export const Knowledge = () => {
  const [articles, setArticles] = useState<Article[]>([]);
  const [term, setTerm] = useState('');

  useEffect(() => {
    getArticles().then(setArticles).catch(() => setArticles([]));
  }, []);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    const results = term ? await searchArticles(term) : await getArticles();
    setArticles(results);
  };

  return (
    <div className="kb-page">
      <h1>Knowledge base</h1>
      <p className="notice">Guides and answers for getting the most out of Sife.</p>
      <form className="ticket-search" onSubmit={submit}>
        <input
          type="search"
          value={term}
          onChange={(event) => setTerm(event.target.value)}
          placeholder="Search the knowledge base…"
        />
        <button className="btn btn-primary" type="submit">
          Search
        </button>
      </form>
      <div className="kb-list">
        {articles.map((article) => (
          <article key={article.slug} className="feature-card">
            <h3>{article.title}</h3>
            <p>{article.body}</p>
            <div className="kb-tags">
              {article.tags?.map((tag) => (
                <span key={tag} className="reaction-chip">
                  {tag}
                </span>
              ))}
            </div>
          </article>
        ))}
      </div>
    </div>
  );
};
