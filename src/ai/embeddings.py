"""
Embedding Manager for NEXUS AI - Semantic similarity and clustering
"""

import numpy as np
import pickle
import logging
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import hashlib
import time

try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    logging.warning("sentence-transformers not available. Install with: pip install sentence-transformers")

try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False
    logging.warning("FAISS not available. Install with: pip install faiss-cpu")

from .config import MLConfig

class EmbeddingManager:
    """Manages text embeddings for similarity detection and clustering"""
    
    def __init__(self, config: MLConfig = None):
        self.config = config or MLConfig()
        self.model = None
        self.embeddings_cache = {}
        self.faiss_index = None
        self.text_to_id = {}
        self.id_to_text = {}
        self.next_id = 0
        
        # Initialize embedding model
        if SENTENCE_TRANSFORMERS_AVAILABLE and self.config.is_enabled():
            self._load_embedding_model()
        
        # Load existing cache and index
        self._load_cache()
        self._load_faiss_index()
    
    def _load_embedding_model(self):
        """Load the sentence transformer model"""
        try:
            model_name = self.config.get_embedding_model()
            self.model = SentenceTransformer(model_name)
            logging.info(f"Loaded embedding model: {model_name}")
        except Exception as e:
            logging.error(f"Failed to load embedding model: {e}")
            self.model = None
    
    def _load_cache(self):
        """Load embeddings cache from disk"""
        try:
            cache_path = self.config.get_embedding_cache_path()
            if cache_path.exists():
                with open(cache_path, 'rb') as f:
                    cache_data = pickle.load(f)
                    self.embeddings_cache = cache_data.get('embeddings', {})
                    self.text_to_id = cache_data.get('text_to_id', {})
                    self.id_to_text = cache_data.get('id_to_text', {})
                    self.next_id = cache_data.get('next_id', 0)
                logging.info(f"Loaded {len(self.embeddings_cache)} cached embeddings")
        except Exception as e:
            logging.warning(f"Failed to load embeddings cache: {e}")
    
    def _save_cache(self):
        """Save embeddings cache to disk"""
        try:
            cache_path = self.config.get_embedding_cache_path()
            cache_data = {
                'embeddings': self.embeddings_cache,
                'text_to_id': self.text_to_id,
                'id_to_text': self.id_to_text,
                'next_id': self.next_id
            }
            with open(cache_path, 'wb') as f:
                pickle.dump(cache_data, f)
        except Exception as e:
            logging.error(f"Failed to save embeddings cache: {e}")
    
    def _load_faiss_index(self):
        """Load FAISS index from disk"""
        if not FAISS_AVAILABLE:
            return
        
        try:
            index_path = self.config.get_faiss_index_path()
            if index_path.exists():
                self.faiss_index = faiss.read_index(str(index_path))
                logging.info(f"Loaded FAISS index with {self.faiss_index.ntotal} vectors")
        except Exception as e:
            logging.warning(f"Failed to load FAISS index: {e}")
    
    def _save_faiss_index(self):
        """Save FAISS index to disk"""
        if not FAISS_AVAILABLE or self.faiss_index is None:
            return
        
        try:
            index_path = self.config.get_faiss_index_path()
            faiss.write_index(self.faiss_index, str(index_path))
        except Exception as e:
            logging.error(f"Failed to save FAISS index: {e}")
    
    def _get_text_hash(self, text: str) -> str:
        """Generate hash for text caching"""
        return hashlib.md5(text.encode()).hexdigest()
    
    def encode_text(self, text: str, use_cache: bool = True) -> Optional[np.ndarray]:
        """Encode single text to embedding vector"""
        if not self.model:
            return None
        
        text_hash = self._get_text_hash(text)
        
        # Check cache first
        if use_cache and text_hash in self.embeddings_cache:
            return self.embeddings_cache[text_hash]
        
        try:
            # Generate embedding
            embedding = self.model.encode([text])[0]
            
            # Cache if enabled
            if use_cache and self.config.get('ml', 'cache_embeddings', True):
                self.embeddings_cache[text_hash] = embedding
                
                # Periodically save cache
                if len(self.embeddings_cache) % 100 == 0:
                    self._save_cache()
            
            return embedding
            
        except Exception as e:
            logging.error(f"Failed to encode text: {e}")
            return None
    
    def encode_batch(self, texts: List[str], use_cache: bool = True) -> List[Optional[np.ndarray]]:
        """Encode multiple texts efficiently"""
        if not self.model:
            return [None] * len(texts)
        
        # Check cache for existing embeddings
        cached_embeddings = {}
        uncached_texts = []
        uncached_indices = []
        
        if use_cache:
            for i, text in enumerate(texts):
                text_hash = self._get_text_hash(text)
                if text_hash in self.embeddings_cache:
                    cached_embeddings[i] = self.embeddings_cache[text_hash]
                else:
                    uncached_texts.append(text)
                    uncached_indices.append(i)
        else:
            uncached_texts = texts
            uncached_indices = list(range(len(texts)))
        
        # Generate embeddings for uncached texts
        new_embeddings = {}
        if uncached_texts:
            try:
                batch_embeddings = self.model.encode(uncached_texts)
                for i, embedding in zip(uncached_indices, batch_embeddings):
                    new_embeddings[i] = embedding
                    
                    # Cache if enabled
                    if use_cache and self.config.get('ml', 'cache_embeddings', True):
                        text_hash = self._get_text_hash(texts[i])
                        self.embeddings_cache[text_hash] = embedding
                        
            except Exception as e:
                logging.error(f"Failed to encode batch: {e}")
                return [None] * len(texts)
        
        # Combine cached and new embeddings
        result = []
        for i in range(len(texts)):
            if i in cached_embeddings:
                result.append(cached_embeddings[i])
            elif i in new_embeddings:
                result.append(new_embeddings[i])
            else:
                result.append(None)
        
        # Save cache if many new embeddings were added
        if len(new_embeddings) > 10:
            self._save_cache()
        
        return result
    
    def build_faiss_index(self, texts: List[str], force_rebuild: bool = False):
        """Build FAISS index for fast similarity search"""
        if not FAISS_AVAILABLE:
            logging.warning("FAISS not available, cannot build index")
            return
        
        if self.faiss_index is not None and not force_rebuild:
            logging.info("FAISS index already exists, use force_rebuild=True to rebuild")
            return
        
        # Generate embeddings
        embeddings = self.encode_batch(texts)
        valid_embeddings = []
        valid_texts = []
        
        for i, (text, embedding) in enumerate(zip(texts, embeddings)):
            if embedding is not None:
                valid_embeddings.append(embedding)
                valid_texts.append(text)
                self.text_to_id[text] = self.next_id
                self.id_to_text[self.next_id] = text
                self.next_id += 1
        
        if not valid_embeddings:
            logging.error("No valid embeddings generated")
            return
        
        # Build FAISS index
        embeddings_array = np.array(valid_embeddings).astype('float32')
        dimension = embeddings_array.shape[1]
        
        # Use IndexFlatIP for cosine similarity
        self.faiss_index = faiss.IndexFlatIP(dimension)
        
        # Normalize vectors for cosine similarity
        faiss.normalize_L2(embeddings_array)
        self.faiss_index.add(embeddings_array)
        
        logging.info(f"Built FAISS index with {len(valid_embeddings)} vectors")
        
        # Save index and cache
        self._save_faiss_index()
        self._save_cache()
    
    def find_similar(self, query_text: str, k: int = 5) -> List[Tuple[str, float]]:
        """Find k most similar texts to query"""
        if not FAISS_AVAILABLE or self.faiss_index is None:
            return []
        
        # Encode query
        query_embedding = self.encode_text(query_text)
        if query_embedding is None:
            return []
        
        # Normalize query vector
        query_vector = query_embedding.reshape(1, -1).astype('float32')
        faiss.normalize_L2(query_vector)
        
        # Search
        try:
            scores, indices = self.faiss_index.search(query_vector, min(k, self.faiss_index.ntotal))
            
            results = []
            for score, idx in zip(scores[0], indices[0]):
                if idx in self.id_to_text:
                    similar_text = self.id_to_text[idx]
                    results.append((similar_text, float(score)))
            
            return results
            
        except Exception as e:
            logging.error(f"FAISS search failed: {e}")
            return []
    
    def calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate cosine similarity between two texts"""
        emb1 = self.encode_text(text1)
        emb2 = self.encode_text(text2)
        
        if emb1 is None or emb2 is None:
            return 0.0
        
        # Cosine similarity
        dot_product = np.dot(emb1, emb2)
        norm1 = np.linalg.norm(emb1)
        norm2 = np.linalg.norm(emb2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return float(dot_product / (norm1 * norm2))
    
    def detect_anomalous_similarity(self, query_text: str, threshold: float = 0.8) -> Dict[str, Any]:
        """Detect if query text is anomalously different from known patterns"""
        similar_texts = self.find_similar(query_text, k=10)
        
        if not similar_texts:
            return {
                'is_anomalous': True,
                'max_similarity': 0.0,
                'reason': 'No similar patterns found',
                'similar_examples': []
            }
        
        max_similarity = max(score for _, score in similar_texts)
        
        return {
            'is_anomalous': max_similarity < threshold,
            'max_similarity': max_similarity,
            'reason': f'Max similarity: {max_similarity:.3f}, threshold: {threshold}',
            'similar_examples': similar_texts[:3]
        }
    
    def cleanup(self):
        """Save all data and cleanup resources"""
        self._save_cache()
        self._save_faiss_index()
        
        if self.model:
            # Clear model from memory if needed
            pass
