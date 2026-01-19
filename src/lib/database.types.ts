export type Database = {
  public: {
    Tables: {
      vulnerability_types: {
        Row: {
          id: string;
          name: string;
          description: string;
          difficulty: 'beginner' | 'intermediate' | 'advanced';
          category: string;
          icon: string | null;
          created_at: string;
        };
        Insert: Omit<Database['public']['Tables']['vulnerability_types']['Row'], 'id' | 'created_at'>;
        Update: Partial<Database['public']['Tables']['vulnerability_types']['Insert']>;
      };
      labs: {
        Row: {
          id: string;
          vulnerability_type_id: string | null;
          title: string;
          description: string;
          instructions: string;
          solution: string;
          points: number;
          created_at: string;
        };
        Insert: Omit<Database['public']['Tables']['labs']['Row'], 'id' | 'created_at'>;
        Update: Partial<Database['public']['Tables']['labs']['Insert']>;
      };
      user_progress: {
        Row: {
          id: string;
          user_id: string;
          module_name: string;
          module_level: string;
          points: number;
          completed_at: string;
          created_at: string;
        };
        Insert: Omit<Database['public']['Tables']['user_progress']['Row'], 'id' | 'created_at'>;
        Update: Partial<Database['public']['Tables']['user_progress']['Insert']>;
      };
      daily_activity: {
        Row: {
          id: string;
          user_id: string;
          activity_date: string;
          modules_completed: number;
          created_at: string;
        };
        Insert: Omit<Database['public']['Tables']['daily_activity']['Row'], 'id' | 'created_at'>;
        Update: Partial<Database['public']['Tables']['daily_activity']['Insert']>;
      };
      store_products: {
        Row: {
          id: string;
          name: string;
          description: string;
          price: number;
          image_url: string | null;
          stock: number;
          created_at: string;
        };
        Insert: Omit<Database['public']['Tables']['store_products']['Row'], 'id' | 'created_at'>;
        Update: Partial<Database['public']['Tables']['store_products']['Insert']>;
      };
    };
  };
};
